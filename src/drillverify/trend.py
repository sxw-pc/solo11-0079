"""Run-clustered, exposure-matched exact trend tests over the audit ledger.

A ledger row is an audit record, not necessarily a new observation. Runs with
the same ``run_id`` count once, findings inside a run form one organic unit, and
only runs sharing the declared plan dataset scope, rule version and
analysis-window convention are compared. Within an exposure layer
(``backup_count``, ``drill_count``) baseline/recent labels are exhaustively
permuted for a one-sided exact p value.

``duty`` takes exactly one pre-registered metric and decides on its exact p.
``overview`` permutes the maximum statistic over every declared metric and
reports raw per-metric p values for audit only.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Sequence

from . import RULE_VERSION
from .ledger import list_run_records
from .rules import category_for

MATERIAL = frozenset({"critical", "high", "error", "medium"})
MODES = frozenset({"duty", "overview"})
DEFAULT_ALPHA = 0.01
DEFAULT_BUDGET = 20000

ASSUMPTIONS = (
    "Only distinct run_ids are observations; repeated ledger writes for one run_id count once.",
    "Each run contributes one binary observation per metric: a material finding of that "
    "rule/severity/category occurred or it did not. Findings are never independent samples.",
    "Comparable runs share plan dataset scope, rule version and analysis-window convention.",
    "Runs are exchangeable only within an identical backup_count/drill_count exposure layer.",
    "Labels keep the declared window sizes; ties count as at least as extreme (one-sided).",
)
CAVEAT = (
    "This is a trend aid, not a compliance or recovery certification. A non-significant "
    "result is not proof of recovery or compliance, and only the declared synthetic "
    "exchangeable scope is interpreted."
)


@dataclass(frozen=True)
class TrendSpec:
    """A pre-registered comparison declaration."""

    metrics: tuple[str, ...]
    baseline_run_ids: tuple[str, ...]
    recent_run_ids: tuple[str, ...]
    mode: str = "overview"
    alpha: float = DEFAULT_ALPHA
    max_permutations: int = DEFAULT_BUDGET


@dataclass(frozen=True)
class RunObservation:
    """One de-duplicated, analysis-ready ledger run."""

    run_id: str
    ledger_ids: tuple[int, ...]
    as_of: str
    status: str
    summary: dict[str, Any]
    findings: tuple[dict[str, str], ...]
    scope: str
    rule_version: str
    window_days: int
    backup_count: int
    drill_count: int
    signature: str

    @property
    def exposure(self) -> tuple[int, int]:
        return (self.backup_count, self.drill_count)


def _metric_parts(metric: str) -> tuple[str, str]:
    kind, _, metric_value = metric.partition(":")
    if kind not in {"rule", "severity", "category"} or not metric_value:
        raise ValueError(
            f"invalid metric {metric!r}; use rule:<id>, severity:<name> or category:<name>")
    return kind, metric_value


def _event(metric: str, finding: dict[str, Any]) -> bool:
    kind, metric_value = _metric_parts(metric)
    severity = str(finding.get("severity", ""))
    if severity not in MATERIAL:
        return False
    if kind == "rule":
        return finding.get("rule_id") == metric_value
    if kind == "severity":
        return severity == metric_value
    category = finding.get("category") or category_for(str(finding.get("rule_id", "")))
    return category == metric_value


def _comparability(report: dict[str, Any]) -> tuple[str, str, int]:
    declared = report.get("comparability")
    if isinstance(declared, dict):
        window = declared.get("analysis_window_days")
        return (str(declared.get("plan_dataset_scope", "")),
                str(declared.get("rule_version", "")),
                window if isinstance(window, int) else 0)
    plan = report.get("plan") or {}
    scope = ",".join(sorted(str(item.get("dataset_id", ""))
                            for item in plan.get("datasets") or []))
    window = plan.get("analysis_window_days")
    return scope, RULE_VERSION, window if isinstance(window, int) else 0


def _observation(record: dict[str, Any]) -> RunObservation:
    report = record.get("report") or {}
    summary = record.get("summary") or report.get("summary") or {}
    scope, version, window = _comparability(report)
    backup, drill = summary.get("backup_count"), summary.get("drill_count")
    if not (isinstance(backup, int) and isinstance(drill, int)):
        backup, drill = len(report.get("backups") or []), len(report.get("drills") or [])
    findings = tuple(
        {"rule_id": str(item.get("rule_id", "")), "severity": str(item.get("severity", "")),
         "category": str(item.get("category") or category_for(str(item.get("rule_id", ""))))}
        for item in report.get("findings") or [])
    status = str(record.get("status", ""))
    signature = repr((status, (backup, drill),
                      tuple(sorted((f["rule_id"], f["severity"], f["category"])
                                   for f in findings))))
    return RunObservation(
        run_id=str(record["run_id"]), ledger_ids=(int(record["id"]),),
        as_of=str(record.get("as_of", "")), status=status, summary=dict(summary),
        findings=findings, scope=scope, rule_version=version, window_days=window,
        backup_count=backup, drill_count=drill, signature=signature)


def collapse(records):
    """Collapse ledger rows by run_id; conflicting duplicates are excluded."""
    grouped: dict[str, list[RunObservation]] = {}
    for record in records:
        observation = _observation(record)
        grouped.setdefault(observation.run_id, []).append(observation)
    observations, duplicates = [], []
    for run_id in sorted(grouped):
        rows = sorted(grouped[run_id], key=lambda item: item.ledger_ids[0])
        ledger_ids = tuple(pk for item in rows for pk in item.ledger_ids)
        if len({item.signature for item in rows}) > 1:
            duplicates.append({"run_id": run_id, "ledger_ids": list(ledger_ids),
                               "resolution": "conflicting duplicate rows excluded"})
            continue
        observations.append(replace(rows[0], ledger_ids=ledger_ids))
        if len(rows) > 1:
            duplicates.append({"run_id": run_id, "ledger_ids": list(ledger_ids),
                               "resolution": "counted once in the statistical sample"})
    return observations, duplicates


def load_observations(db_path: Path) -> tuple[list[RunObservation], list[dict[str, Any]]]:
    """Load ledger rows, retaining duplicates in audit but counting them once."""
    return collapse(list_run_records(db_path))


def build_spec(mode: str, metrics: Sequence[str], baseline_run_ids: Sequence[str],
               recent_run_ids: Sequence[str], alpha: float = DEFAULT_ALPHA,
               max_permutations: int = DEFAULT_BUDGET) -> TrendSpec:
    """Normalize and freeze the declaration before outcomes are inspected."""
    unique = tuple(sorted({metric.strip() for metric in metrics if metric.strip()}))
    return TrendSpec(unique, tuple(dict.fromkeys(baseline_run_ids)),
                     tuple(dict.fromkeys(recent_run_ids)), mode, alpha, max_permutations)


def analyze_runs(records: Sequence[dict[str, Any]], spec: TrendSpec) -> dict[str, Any]:
    """Analyze raw ledger-shaped records; audit duplicates are retained."""
    from .trend_test import analyze_observations

    observations, duplicates = collapse(records)
    return analyze_observations(observations, duplicates, spec)


def analyze_ledger(db_path: Path, spec: TrendSpec) -> dict[str, Any]:
    """Load the ledger and run the declared exact trend test."""
    from .trend_test import analyze_observations

    observations, duplicates = load_observations(db_path)
    return analyze_observations(observations, duplicates, spec)
