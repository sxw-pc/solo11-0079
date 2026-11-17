"""End-to-end orchestration of the offline verification pipeline."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from . import REPORT_VERSION, __version__
from .actions import AttributionRecord, PlanAction
from .attribution import attribute
from .backup_chain import ChainAssessment, assess_chains
from .config import load_plan
from .consistency import DrillAssessment, assess_drills
from .evidence import ArtifactAssessment, EvidenceAssessment, assess_artifacts, assess_evidence
from .loaders import load_catalog, load_drills
from .models import FileFingerprint, Finding, RecoveryPlan
from .objectives import ObjectiveAssessment, evaluate_rpo, evaluate_rto
from .paths import sha256_bytes, stable_json
from .planner import build_plan
from .records import ArtifactCheck, BackupRecord, DrillEvent, EvidenceCheck
from .results import (
    BackupChainResult,
    DrillSummary,
    RestorablePoint,
    RpoResult,
    RtoResult,
)
from .timeutil import format_utc
from .validators import validate_catalog, validate_drills


class PipelineError(RuntimeError):
    """Raised only when the plan cannot produce a run at all."""

    def __init__(self, message: str, findings: tuple[Finding, ...] = ()) -> None:
        super().__init__(message)
        self.findings = findings


@dataclass(frozen=True)
class RunBundle:
    run_id: str
    plan: RecoveryPlan
    findings: tuple[Finding, ...]
    artifacts: tuple[ArtifactCheck, ...]
    evidence: tuple[EvidenceCheck, ...]
    chains: tuple[BackupChainResult, ...]
    points: tuple[RestorablePoint, ...]
    drills: tuple[DrillSummary, ...]
    rpo: tuple[RpoResult, ...]
    rto: tuple[RtoResult, ...]
    attribution: tuple[AttributionRecord, ...]
    attribution_summary: dict[str, Any]
    actions: tuple[PlanAction, ...]
    plan_summary: dict[str, Any]
    inputs: tuple[FileFingerprint, ...]
    backups: tuple[BackupRecord, ...]
    events: tuple[DrillEvent, ...]
    status: str
    summary: dict[str, Any]
    dataset_summaries: tuple[dict[str, Any], ...]

    @property
    def counts(self) -> dict[str, int]:
        return Counter(item.severity for item in self.findings)


def _overall_status(findings: tuple[Finding, ...]) -> str:
    if any(item.severity in {"critical", "high", "error"} for item in findings):
        return "fail"
    if any(item.severity in {"medium", "warning"} for item in findings):
        return "warn"
    return "pass"


def _dedupe_findings(
    findings: list[Finding], catalog_hash: str, drill_hash: str
) -> tuple[Finding, ...]:
    unique = {item.dedupe_key(): item for item in findings}
    traced: list[Finding] = []
    for item in unique.values():
        if not item.input_sha256:
            if item.rule_id.startswith("ART-") and catalog_hash:
                item = replace(item, input_sha256=catalog_hash)
            elif item.rule_id.startswith("EVID-") and drill_hash:
                item = replace(item, input_sha256=drill_hash)
        traced.append(item)
    return tuple(sorted(traced, key=Finding.sort_key))


def _dataset_summaries(
    plan: RecoveryPlan,
    findings: tuple[Finding, ...],
    points: tuple[RestorablePoint, ...],
    rpo: tuple[RpoResult, ...],
    rto: tuple[RtoResult, ...],
    drills: tuple[DrillSummary, ...],
    backups: tuple[BackupRecord, ...],
    events: tuple[DrillEvent, ...],
) -> tuple[dict[str, Any], ...]:
    rpo_map = {item.dataset_id: item for item in rpo}
    owners = plan.dataset_map()
    rows: list[dict[str, Any]] = []
    for dataset in plan.datasets:
        dataset_id = dataset.dataset_id
        backup_ids = {item.backup_id for item in backups if item.dataset_id == dataset_id}
        drill_ids = {item.drill_id for item in events if item.dataset_id == dataset_id}
        related = [
            item
            for item in findings
            if item.object_id == dataset_id
            or item.object_id in backup_ids
            or item.object_id in drill_ids
        ]
        material = [
            item
            for item in related
            if item.severity in {"critical", "high", "error", "medium"}
        ]
        if material:
            status = "fail"
        elif related:
            status = "warn"
        else:
            status = "pass"
        window_points = [
            item
            for item in points
            if item.dataset_id == dataset_id
            and plan.window_start <= item.finished_at <= plan.as_of
        ]
        dataset_drills = [item for item in drills if item.dataset_id == dataset_id]
        dataset_rto = [item for item in rto if item.dataset_id == dataset_id]
        rows.append(
            {
                "dataset_id": dataset_id,
                "display_name": owners[dataset_id].display_name,
                "owner_team": owners[dataset_id].owner_team,
                "status": status,
                "rpo": rpo_map[dataset_id].to_dict(),
                "point_count": len(window_points),
                "last_point_at": (
                    format_utc(window_points[-1].finished_at) if window_points else None
                ),
                "drill_count": len(dataset_drills),
                "successful_drills": sum(1 for item in dataset_drills if item.status == "success"),
                "rto_statuses": sorted({item.status for item in dataset_rto}),
                "finding_count": len(related),
                "material_finding_count": len(material),
            }
        )
    return tuple(rows)


def run_pipeline(fixtures_root: Path) -> RunBundle:
    """Run all stages without writing reports or touching a database."""
    root = fixtures_root.resolve()
    plan_load = load_plan(root / "plans" / "recovery_plan.yaml", root)
    if plan_load.plan is None:
        raise PipelineError("Recovery plan is unusable.", plan_load.findings)
    plan = plan_load.plan

    catalog_load = load_catalog(root)
    drill_load = load_drills(root)
    catalog = validate_catalog(catalog_load, plan, root)
    drills = validate_drills(drill_load, plan, catalog.records, root)
    catalog_hash = catalog_load.fingerprint.sha256 if catalog_load.fingerprint else ""
    drill_hash = drill_load.fingerprint.sha256 if drill_load.fingerprint else ""
    artifact_assessment: ArtifactAssessment = assess_artifacts(catalog.records, plan, root)
    evidence_assessment: EvidenceAssessment = assess_evidence(drills.events, root)
    chain_assessment: ChainAssessment = assess_chains(
        plan,
        catalog.records,
        artifact_assessment.checks,
        catalog_load.path,
        catalog_hash,
    )
    drill_assessment: DrillAssessment = assess_drills(
        plan,
        drills.events,
        catalog.records,
        chain_assessment.chains,
        artifact_assessment.manifests,
        evidence_assessment.ok_refs(),
        drill_load.path,
        drill_hash,
    )
    rpo, rpo_findings = evaluate_rpo(
        plan,
        chain_assessment.points,
        catalog_load.path,
        catalog_hash,
    )
    rto, rto_findings = evaluate_rto(
        plan,
        drills.events,
        drill_assessment.success,
        drill_load.path,
        drill_hash,
    )
    objective_assessment = ObjectiveAssessment(rpo, rto, rpo_findings + rto_findings)

    all_findings = list(plan_load.findings)
    all_findings.extend(catalog.findings)
    all_findings.extend(drills.findings)
    all_findings.extend(artifact_assessment.findings)
    all_findings.extend(evidence_assessment.findings)
    all_findings.extend(chain_assessment.findings)
    all_findings.extend(drill_assessment.findings)
    all_findings.extend(objective_assessment.findings)
    findings = _dedupe_findings(all_findings, catalog_hash, drill_hash)
    records, attribution_summary = attribute(findings)
    actions, plan_summary = build_plan(plan, findings, catalog.records, drills.events)

    fingerprints: dict[str, FileFingerprint] = {}
    for fingerprint in (
        ([plan_load.fingerprint] if plan_load.fingerprint else [])
        + ([catalog_load.fingerprint] if catalog_load.fingerprint else [])
        + ([drill_load.fingerprint] if drill_load.fingerprint else [])
        + list(artifact_assessment.files)
        + list(evidence_assessment.files)
    ):
        fingerprints[fingerprint.path] = fingerprint
    inputs = tuple(sorted(fingerprints.values(), key=lambda item: item.path))
    run_seed = {
        "report_version": REPORT_VERSION,
        "tool_version": __version__,
        "as_of": format_utc(plan.as_of),
        "analysis_window_days": plan.analysis_window_days,
        "datasets": [item.dataset_id for item in plan.datasets],
        "inputs": [item.to_dict() for item in inputs],
    }
    run_id = sha256_bytes(stable_json(run_seed).encode("utf-8"))[:16]
    status = _overall_status(findings)
    severity_counts = Counter(item.severity for item in findings)
    dataset_summaries = _dataset_summaries(
        plan,
        findings,
        chain_assessment.points,
        rpo,
        rto,
        drill_assessment.summaries,
        catalog.records,
        drills.events,
    )
    summary = {
        "overall_status": status,
        "finding_count": len(findings),
        "finding_counts": {key: severity_counts[key] for key in sorted(severity_counts)},
        "dataset_count": len(plan.datasets),
        "backup_count": len(catalog.records),
        "restorable_point_count": len(chain_assessment.points),
        "drill_count": len(drill_assessment.summaries),
        "successful_drill_count": sum(
            1 for item in drill_assessment.summaries if item.status == "success"
        ),
        "rpo_breaches": sum(1 for item in rpo if item.status in {"breach", "no_points"}),
        "rto_breaches": sum(1 for item in rto if item.status == "breach"),
        "action_count": len(actions),
        "input_file_count": len(inputs),
        "validation_rejected_rows": catalog.rejected_count + drills.rejected_count,
    }
    return RunBundle(
        run_id=run_id,
        plan=plan,
        findings=findings,
        artifacts=artifact_assessment.checks,
        evidence=evidence_assessment.checks,
        chains=chain_assessment.chains,
        points=chain_assessment.points,
        drills=drill_assessment.summaries,
        rpo=rpo,
        rto=rto,
        attribution=records,
        attribution_summary=attribution_summary,
        actions=actions,
        plan_summary=plan_summary,
        inputs=inputs,
        backups=catalog.records,
        events=drills.events,
        status=status,
        summary=summary,
        dataset_summaries=dataset_summaries,
    )
