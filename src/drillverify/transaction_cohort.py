"""Offline cross-dataset settled-transaction cohort verification.

Verdicts are proven inside one bounded integer feasibility domain over the
summary-bundle attributions of a plan-declared cohort of restorable points.
No restore is run and no closest recovery cut is searched; the verdict
never inherits RPO, RTO or the report clock.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from .models import CohortMemberSpec, CohortSpec, CohortSpecLoad, FileFingerprint, Finding
from .models import RecoveryPlan, RoleContract
from .paths import safe_relative, sha256_file
from .records import TRANSACTION_ROLES, ArtifactManifest, BackupRecord, TransactionContribution
from .results import AssignmentWitness, CohortMemberResult, CohortProof, CohortResult, RestorablePoint
from .timeutil import format_utc

COHORT_SPEC_PATH = "plans/transaction_cohorts.yaml"
PURPOSES = ("strict_publish", "triage_review")
DEFAULT_SEARCH_BUDGET = 100_000
MAX_SEARCH_BUDGET = 2_000_000
MAX_CONSERVING_WITNESSES = 3
_ID_RE = re.compile(r"^[a-z][a-z0-9-]{2,63}$")
_SHA_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _parse_cohort_spec(item: object, known: set[str]) -> tuple[CohortSpec | None, list[str]]:
    if not isinstance(item, dict):
        return None, ["cohort entry must be an object"]
    cohort_id = item.get("cohort_id")
    if not isinstance(cohort_id, str) or not _ID_RE.fullmatch(cohort_id):
        return None, ["cohort_id is invalid"]
    errors: list[str] = []
    purpose = item.get("purpose")
    if purpose not in PURPOSES:
        errors.append(f"purpose must be one of {', '.join(PURPOSES)}")
    members: list[CohortMemberSpec] = []
    members_raw = item.get("members")
    if not isinstance(members_raw, list) or len(members_raw) < 2:
        errors.append("members must list at least two restorable points")
        members_raw = []
    seen: set[str] = set()
    for index, member in enumerate(members_raw):
        if not isinstance(member, dict):
            errors.append(f"members[{index}] must be an object")
            continue
        dataset_id, backup_id = member.get("dataset_id"), member.get("backup_id")
        pinned = member.get("expected_manifest_sha256")
        if dataset_id not in known:
            errors.append(f"members[{index}].dataset_id is not a declared dataset")
        if not isinstance(backup_id, str) or not _ID_RE.fullmatch(backup_id):
            errors.append(f"members[{index}].backup_id is invalid")
            backup_id = ""
        if pinned is not None and (not isinstance(pinned, str) or not _SHA_RE.fullmatch(pinned)):
            errors.append(f"members[{index}].expected_manifest_sha256 must be 64 hex characters")
            pinned = None
        if backup_id and backup_id in seen:
            errors.append(f"backup {backup_id} is listed twice")
        if backup_id and isinstance(dataset_id, str):
            seen.add(backup_id)
            members.append(CohortMemberSpec(
                dataset_id, backup_id, pinned.lower() if isinstance(pinned, str) else None))
    if members and len({member.dataset_id for member in members}) < 2:
        errors.append("members must span at least two datasets")

    def role_list(key: str) -> list[str]:
        value = item.get(key)
        if (not isinstance(value, list) or not value or len(set(value)) != len(value)
                or any(role not in TRANSACTION_ROLES for role in value)):
            errors.append(f"{key} must be unique roles from {', '.join(TRANSACTION_ROLES)}")
            return []
        return list(value)

    required, anchors = role_list("required_roles"), role_list("anchor_roles")
    if required and anchors and any(role not in required for role in anchors):
        errors.append("anchor_roles must be a subset of required_roles")
    sources_raw = item.get("role_sources")
    sources: dict[str, tuple[str, ...]] = {}
    if not isinstance(sources_raw, dict):
        errors.append("role_sources must map each required role to source datasets")
        sources_raw = {}
    for role in required:
        datasets = sources_raw.get(role)
        if not isinstance(datasets, list) or not datasets or any(ds not in known for ds in datasets):
            errors.append(f"role_sources.{role} must list declared dataset ids")
        else:
            sources[role] = tuple(sorted(set(datasets)))
    extra = sorted(set(sources_raw) - set(required))
    if extra:
        errors.append(f"role_sources lists unknown roles: {', '.join(extra)}")
    budget = item.get("search_budget", DEFAULT_SEARCH_BUDGET)
    if isinstance(budget, bool) or not isinstance(budget, int) or not 1 <= budget <= MAX_SEARCH_BUDGET:
        errors.append(f"search_budget must be an integer from 1 to {MAX_SEARCH_BUDGET}")
        budget = DEFAULT_SEARCH_BUDGET
    if errors:
        return None, errors
    return CohortSpec(cohort_id, purpose, tuple(members),
                      RoleContract(tuple(required), tuple(anchors), sources), budget), []


def load_cohort_specs(fixtures_root: Path, plan: RecoveryPlan) -> CohortSpecLoad:
    """Load the optional cohort contract file; an absent file means no cohorts."""
    root = fixtures_root.resolve()
    path = root / COHORT_SPEC_PATH
    rel_path = safe_relative(root, path)
    if not path.is_file():
        return CohortSpecLoad((), (), None, rel_path)
    fingerprint = FileFingerprint(rel_path, sha256_file(path), path.stat().st_size)

    def issue(message: str, object_id: str) -> Finding:
        return Finding("TXN-001", "error", "cohort", object_id, message, rel_path, 0, {},
                       fingerprint.sha256)

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        bad = issue(f"Cohort spec cannot be parsed: {type(exc).__name__}.", rel_path)
        return CohortSpecLoad((), (bad,), fingerprint, rel_path)
    cohorts = raw.get("cohorts") if isinstance(raw, dict) else None
    if not isinstance(cohorts, list):
        bad = issue("Cohort spec must hold a cohorts list.", rel_path)
        return CohortSpecLoad((), (bad,), fingerprint, rel_path)
    known = {dataset.dataset_id for dataset in plan.datasets}
    findings: list[Finding] = []
    specs: list[CohortSpec] = []
    seen_ids: set[str] = set()
    for index, item in enumerate(cohorts):
        spec, errors = _parse_cohort_spec(item, known)
        label = item.get("cohort_id") if isinstance(item, dict) else None
        object_id = label if isinstance(label, str) and label else f"cohorts[{index}]"
        if spec is None:
            findings.append(issue("Cohort spec entry is invalid: " + "; ".join(errors) + ".", object_id))
        elif spec.cohort_id in seen_ids:
            findings.append(issue("cohort_id is declared more than once.", spec.cohort_id))
        else:
            seen_ids.add(spec.cohort_id)
            specs.append(spec)
    return CohortSpecLoad(tuple(specs), tuple(sorted(findings, key=Finding.sort_key)), fingerprint, rel_path)


def refines(anchor: str, mask: str) -> bool:
    """True when ``anchor`` keeps every concrete character of ``mask``."""
    return len(anchor) == len(mask) and all(m == "*" or m == a for a, m in zip(anchor, mask))


def solve_attributions(
    contributions: tuple[TransactionContribution, ...],
    required_roles: tuple[str, ...], anchor_roles: tuple[str, ...], budget: int,
) -> CohortProof:
    """Enumerate every legal attribution once; report exact min/max net gap."""
    anchors = sorted({c.tx_ref_masked for c in contributions if c.role in anchor_roles})
    candidates = {c.part_id: [a for a in anchors if refines(a, c.tx_ref_masked)] for c in contributions}
    unassigned = tuple(sorted(c.part_id for c in contributions if not candidates[c.part_id]))
    state: dict[str, Any] = {"nodes": 0, "evaluated": 0, "exhausted": False, "conserving": []}
    best: dict[str, AssignmentWitness | None] = {"min": None, "max": None}

    def proof(status: str, cause: str, **overrides: Any) -> CohortProof:
        base: dict[str, Any] = dict(
            status=status, cause=cause, contribution_count=len(contributions),
            transaction_count=len(anchors), nodes_explored=state["nodes"],
            assignments_evaluated=state["evaluated"], budget=budget, min_gap=None,
            max_gap=None, min_witness=None, max_witness=None, conserving_witnesses=(),
            unassigned_part_ids=unassigned)
        return CohortProof(**{**base, **overrides})

    if not contributions or not anchors or unassigned:
        return proof("inconclusive", "no_legal_assignment")
    order = sorted(contributions, key=lambda c: (len(candidates[c.part_id]), c.part_id))
    chosen: dict[str, str] = {}

    def leaf() -> AssignmentWitness | None:
        totals: dict[str, dict[str, int]] = {}
        for item in contributions:
            bucket = totals.setdefault(chosen[item.part_id], {})
            bucket[item.role] = bucket.get(item.role, 0) + item.amount
        gaps: list[tuple[str, int]] = []
        for anchor in sorted(totals):
            roles = totals[anchor]
            if any(role not in roles for role in required_roles):
                return None
            gaps.append((anchor, max(roles[r] for r in required_roles) - min(roles[r] for r in required_roles)))
        return AssignmentWitness(
            tuple(sorted((c.part_id, chosen[c.part_id]) for c in contributions)),
            sum(gap for _, gap in gaps), tuple(gaps))

    def dfs(index: int) -> None:
        if state["exhausted"]:
            return
        state["nodes"] += 1
        if state["nodes"] > budget:
            state["exhausted"] = True
            return
        if index == len(order):
            candidate = leaf()
            if candidate is None:
                return
            state["evaluated"] += 1
            for key, sign in (("min", 1), ("max", -1)):
                current = best[key]
                if current is None or sign * (candidate.total_gap - current.total_gap) < 0 or (
                    candidate.total_gap == current.total_gap
                    and candidate.assignments < current.assignments
                ):
                    best[key] = candidate
            if candidate.total_gap == 0 and len(state["conserving"]) < MAX_CONSERVING_WITNESSES:
                state["conserving"].append(candidate)
            return
        part = order[index].part_id
        for anchor in candidates[part]:
            chosen[part] = anchor
            dfs(index + 1)
            if state["exhausted"]:
                return
        chosen.pop(part, None)

    dfs(0)
    if state["exhausted"]:
        return proof("inconclusive", "budget_exceeded",
                     min_gap=best["min"].total_gap if best["min"] else None,
                     max_gap=best["max"].total_gap if best["max"] else None,
                     min_witness=best["min"], max_witness=best["max"],
                     conserving_witnesses=tuple(state["conserving"]), unassigned_part_ids=())
    if state["evaluated"] == 0:
        return proof("inconclusive", "no_legal_assignment", unassigned_part_ids=())
    minimum, maximum = best["min"], best["max"]
    assert minimum is not None and maximum is not None
    if maximum.total_gap == 0:
        status = "proven_consistent"
    elif minimum.total_gap > 0:
        status = "proven_conflict"
    else:
        status = "pending_review"
    return proof(status, "", min_gap=minimum.total_gap, max_gap=maximum.total_gap,
                 min_witness=minimum, max_witness=maximum,
                 conserving_witnesses=tuple(state["conserving"]), unassigned_part_ids=())


def evaluate_cohort(
    spec: CohortSpec,
    points: tuple[RestorablePoint, ...],
    manifests: dict[str, ArtifactManifest],
    manifest_fingerprints: dict[str, str],
    backups: tuple[BackupRecord, ...],
) -> CohortResult:
    """Verify one cohort of fixed restorable points without restoring anything."""
    point_index = {(p.dataset_id, p.backup_id): p for p in points}
    backup_ids = {item.backup_id for item in backups}

    def result(status: str, cause: str, members: list[CohortMemberResult],
               proof: CohortProof | None = None, contribution_count: int = 0,
               detail: str = "", window_end: str = "") -> CohortResult:
        gate = "not_applicable" if spec.purpose != "strict_publish" else (
            "released" if status == "proven_consistent" else "paused")
        return CohortResult(spec.cohort_id, spec.purpose, status, cause, tuple(members),
                            contribution_count, proof, gate, status == "pending_review",
                            "transaction_summary", window_end, detail)

    members: list[CohortMemberResult] = []
    for member in spec.members:
        point = point_index.get((member.dataset_id, member.backup_id))
        members.append(CohortMemberResult(
            member.dataset_id, member.backup_id, format_utc(point.finished_at) if point else "",
            manifest_fingerprints.get(member.backup_id, "")))
        if point is None:
            cause = "member_not_restorable" if member.backup_id in backup_ids else "missing_member"
            return result("inconclusive", cause, members, detail=f"{member.dataset_id}/{member.backup_id}")
    for member, outcome in zip(spec.members, members):
        pinned = member.expected_manifest_sha256
        if pinned is not None and outcome.manifest_sha256 != pinned:
            return result("inconclusive", "fingerprint_mismatch", members,
                          detail=f"{member.dataset_id}/{member.backup_id}")
    pool: list[TransactionContribution] = []
    for member in spec.members:
        manifest = manifests.get(member.backup_id)
        summary = manifest.transaction_summary if manifest else None
        if summary is None:
            cause = "invalid_summary" if manifest and manifest.transaction_summary_error else "missing_summary"
            return result("inconclusive", cause, members, detail=member.backup_id)
        pool.extend(summary)
    seen: set[str] = set()
    duplicates = sorted({c.part_id for c in pool if c.part_id in seen or seen.add(c.part_id)})
    if duplicates:
        return result("inconclusive", "invalid_summary", members, contribution_count=len(pool),
                      detail="duplicate part_id: " + ", ".join(duplicates))
    contract = spec.role_contract
    for item in pool:
        sources = contract.role_sources.get(item.role, ())
        if item.role not in contract.required_roles or (sources and item.dataset_id not in sources):
            return result("inconclusive", "invalid_summary", members, contribution_count=len(pool),
                          detail=f"role {item.role} from {item.dataset_id} violates the role contract")
    proof = solve_attributions(tuple(pool), contract.required_roles, contract.anchor_roles,
                               spec.search_budget)
    return result(proof.status, proof.cause, members, proof, len(pool),
                  window_end=max(item.finished_at for item in members))
