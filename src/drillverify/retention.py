"""Read-only conditional retention simulation.

Models how chain restorability, RPO conclusions and reclaimable capacity would
change if a set of verified backups were deleted. Nothing is deleted and the
audit ledger is never written: every plan is a conditional simulation that
requires human review before execution. Only verified, traceable artifacts
are modelled (artifact file present, size and SHA-256 matching the catalog,
manifest consistent). Deleting a backup recomputes the restorability of every
descendant chain; the remaining points recompute each dataset's adjacent
in-window gaps, the final gap to ``as_of`` and the RPO conclusion. Deletion
never creates restorable points, so feasibility is monotone and supersets of
an infeasible set are pruned. A dataset whose original RPO verification fails
is never reported as compliant after cleanup and must not lose restorable
points. Capacity is deduplicated per physical file: bytes are released only
when every verified backup referencing the file is deleted. More than
``MAX_CANDIDATES`` candidates aborts the exact search (``over_limit``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from .backup_chain import ancestor_map, assess_chains
from .models import RecoveryPlan
from .objectives import evaluate_rpo, summarize_rpo
from .records import ArtifactCheck, BackupRecord
from .results import RestorablePoint, RpoResult

MAX_CANDIDATES = 16
OBJECTIVE_MAX_BYTES = "max_bytes"
OBJECTIVE_MAX_MIN_MARGIN = "max_min_margin"
DEFAULT_OBJECTIVES = (OBJECTIVE_MAX_BYTES, OBJECTIVE_MAX_MIN_MARGIN)
SIMULATION_NOTE = ("Conditional simulation only: no backup files were deleted and the audit "
                   "ledger was not modified. Every candidate plan requires human review before any execution.")
CAPACITY_RULE = ("Physical files are deduplicated by canonical artifact path; bytes are reclaimable "
                 "only when every verified backup referencing the file is deleted.")
TIE_BREAK_RULES = ("max_bytes: most released bytes, largest tightest RPO margin, fewest deletions, "
                   "smallest sorted backup ids. max_min_margin: largest tightest RPO margin among "
                   "sets releasing at least min_reclaim_bytes, then most bytes, fewest deletions, "
                   "smallest sorted backup ids.")
# One evaluated deletion set: (feasible, released_bytes, tightest_margin, members).
_Eval = tuple[bool, int, "int | None", frozenset]

@dataclass(frozen=True)
class RetentionAssessment:
    """Report-ready conditional retention plans; never executed."""

    report: dict[str, Any]
    simulation: bool = True
    requires_human_review: bool = True

    @property
    def status(self) -> str:
        return self.report["status"]

    @property
    def plans(self) -> list[dict[str, Any]]:
        return self.report["plans"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "simulation": self.simulation, "requires_human_review": self.requires_human_review,
            "executed": False, "simulation_note": SIMULATION_NOTE,
            "capacity_rule": CAPACITY_RULE, "tie_break_rules": TIE_BREAK_RULES, **self.report,
        }

def _rank(evaluation: _Eval, margin_first: bool) -> tuple:
    _, size, margin, members = evaluation
    margin = margin if margin is not None else -1
    head = (margin, size) if margin_first else (size, margin)
    return head + (-len(members),)

def _better(candidate: _Eval, incumbent: _Eval | None, margin_first: bool) -> bool:
    if incumbent is None:
        return True
    new, old = _rank(candidate, margin_first), _rank(incumbent, margin_first)
    return new > old if new != old else sorted(candidate[3]) < sorted(incumbent[3])

class _Model:
    """Order-independent view of the verified backup inventory."""

    def __init__(self, plan: RecoveryPlan, records: tuple[BackupRecord, ...],
                 artifacts: tuple[ArtifactCheck, ...], points: tuple[RestorablePoint, ...],
                 baseline_rpo: tuple[RpoResult, ...]) -> None:  # noqa: E501
        self.plan = plan
        self.records = {item.backup_id: item for item in records}
        self.sorted_records = tuple(sorted(records, key=lambda item: item.backup_id))
        self.sorted_artifacts = tuple(sorted(artifacts, key=lambda item: item.backup_id))
        ready = {item.backup_id for item in artifacts if item.artifact_ready}
        self.eligible = tuple(sorted(ready & set(self.records)))
        self.points = tuple(sorted(points, key=lambda p: (p.dataset_id, p.finished_at, p.backup_id)))
        self.point_by_id = {item.backup_id: item for item in self.points}
        self.baseline = {item.dataset_id: item.status for item in baseline_rpo}
        ancestors = ancestor_map(tuple(self.sorted_records))
        kill: dict[str, set[str]] = {}
        for point in self.points:
            for ancestor in ancestors.get(point.backup_id, (point.backup_id,)):
                kill.setdefault(ancestor, set()).add(point.backup_id)
        self.kill = {key: frozenset(value) for key, value in kill.items()}
        self.dataset_points = {
            dataset.dataset_id: tuple(p.backup_id for p in self.points if p.dataset_id == dataset.dataset_id)
            for dataset in plan.datasets
        }
        self.file_size: dict[str, int] = {}
        self.file_sha: dict[str, str] = {}
        refs: dict[str, set[str]] = {}
        for backup_id in self.eligible:
            record = self.records[backup_id]
            self.file_size[record.artifact_path] = record.artifact_size_bytes
            self.file_sha[record.artifact_path] = record.sha256
            refs.setdefault(record.artifact_path, set()).add(backup_id)
        self.file_refs = {path: frozenset(ids) for path, ids in refs.items()}

    def released_bytes(self, members: frozenset[str]) -> int:
        return sum(self.file_size[p] for p, refs in self.file_refs.items() if refs <= members)

    def evaluate(self, members: frozenset[str]) -> _Eval:
        killed: set[str] = set()
        for backup_id in members:
            killed |= self.kill.get(backup_id, frozenset())
        margins: list[int] = []
        for dataset_id in sorted(self.dataset_points):
            baseline_ids = self.dataset_points[dataset_id]
            remaining = [item for item in baseline_ids if item not in killed]
            if self.baseline.get(dataset_id) != "pass":
                # Already non-compliant: must not lose any restorable point.
                if len(remaining) != len(baseline_ids):
                    return (False, 0, None, members)
                continue
            dataset = self.plan.dataset_map()[dataset_id]
            result = summarize_rpo(dataset, self.plan.window_start, self.plan.as_of,
                                   [self.point_by_id[item] for item in remaining])
            if result.status != "pass":
                return (False, 0, None, members)
            margins.append(result.rpo_minutes - (result.max_gap_minutes or 0))
        margin = min(margins) if margins else None
        return (True, self.released_bytes(members), margin, members)

    def build_plan(self, objective: str, min_reclaim_bytes: int, chosen: _Eval,
                   feasible: bool, reason: str, upper: int,
                   catalog_path: str, catalog_hash: str) -> dict[str, Any]:
        members = chosen[3] if feasible else frozenset()
        # Recompute descendant chains and RPO conclusions from scratch on the
        # remaining inventory; nothing is deleted outside this simulation.
        remaining_records = tuple(r for r in self.sorted_records if r.backup_id not in members)
        remaining_artifacts = tuple(a for a in self.sorted_artifacts if a.backup_id not in members)
        chains = assess_chains(self.plan, remaining_records, remaining_artifacts,
                               catalog_path, catalog_hash)
        rpo_after, _ = evaluate_rpo(self.plan, chains.points, catalog_path, catalog_hash)
        rpo_map = {item.dataset_id: item for item in rpo_after}
        datasets: list[dict[str, Any]] = []
        for dataset in self.plan.datasets:
            after = rpo_map[dataset.dataset_id]
            baseline = self.baseline.get(dataset.dataset_id, "no_points")
            margin = after.rpo_minutes - after.max_gap_minutes if after.max_gap_minutes is not None else None
            datasets.append({
                "dataset_id": dataset.dataset_id, "baseline_status": baseline,
                "status": after.status,
                "compliant_after": baseline == "pass" and after.status == "pass",
                "rpo_minutes": after.rpo_minutes, "max_gap_minutes": after.max_gap_minutes,
                "minutes_since_last_point": after.minutes_since_last_point,
                "margin_minutes": margin,
                "retained_points": [
                    p.backup_id for p in chains.points
                    if p.dataset_id == dataset.dataset_id
                    and self.plan.window_start <= p.finished_at <= self.plan.as_of
                ],
                "note": "" if baseline == "pass" else "pre_existing_non_compliance",
            })
        deletions = []
        for backup_id in sorted(members):
            record = self.records[backup_id]
            deletions.append({
                "backup_id": backup_id, "dataset_id": record.dataset_id,
                "backup_type": record.backup_type,
                "artifact_path": record.artifact_path, "input_sha256": record.sha256,
                "artifact_size_bytes": record.artifact_size_bytes,
                "affected_descendants": sorted(
                    p for p in self.kill.get(backup_id, frozenset()) if p != backup_id
                ),
            })
        released: list[dict[str, Any]] = []
        shared: list[dict[str, Any]] = []
        for path in sorted(self.file_refs):
            refs = self.file_refs[path]
            proof = {
                "path": path, "sha256": self.file_sha[path], "size_bytes": self.file_size[path],
                "referenced_by": sorted(refs), "retained_by": sorted(refs - members),
            }
            if not proof["retained_by"]:
                released.append(proof)
            elif refs & members:
                shared.append(proof)
        margins = [d["margin_minutes"] for d in datasets
                   if d["baseline_status"] == "pass" and d["margin_minutes"] is not None]
        return {
            "objective": objective, "feasible": feasible, "reason": reason,
            "simulation": True, "requires_human_review": True,
            "min_reclaim_bytes": min_reclaim_bytes,
            "deletion_count": len(deletions), "deletions": deletions,
            "total_reclaimable_bytes": sum(item["size_bytes"] for item in released),
            "capacity_upper_bound_bytes": upper,
            "tightest_margin_minutes": min(margins) if margins else None,
            "capacity_proof": {
                "rule": CAPACITY_RULE, "released_files": released,
                "shared_files_retained": shared,
            },
            "datasets": datasets,
        }

def _search(model: _Model, candidates: tuple[str, ...],
            min_reclaim_bytes: int) -> tuple[_Eval, _Eval | None]:
    """Exact deterministic search over the candidate power set with pruning."""
    ordered = tuple(sorted(candidates))
    best_bytes = model.evaluate(frozenset())
    best_margin: _Eval | None = None

    def dfs(position: int, members: frozenset[str]) -> None:
        nonlocal best_bytes, best_margin
        current = model.evaluate(members)
        if not current[0]:
            return  # supersets of an infeasible set are infeasible: prune
        if _better(current, best_bytes, margin_first=False):
            best_bytes = current
        if current[1] >= min_reclaim_bytes and _better(current, best_margin, margin_first=True):
            best_margin = current
        for index in range(position, len(ordered)):
            dfs(index + 1, members | {ordered[index]})

    dfs(0, frozenset())
    return best_bytes, best_margin

def assess_retention(plan: RecoveryPlan, records: tuple[BackupRecord, ...],
                     artifacts: tuple[ArtifactCheck, ...], points: tuple[RestorablePoint, ...],
                     baseline_rpo: tuple[RpoResult, ...], *,
                     objectives: Iterable[str] = DEFAULT_OBJECTIVES,
                     min_reclaim_bytes: int = 0, max_candidates: int = MAX_CANDIDATES,
                     catalog_path: str = "", catalog_hash: str = "") -> RetentionAssessment:
    """Compute conditional retention plans without touching any input.

    ``max_bytes`` releases as many bytes as possible while every RPO still
    passes; ``max_min_margin`` releases at least ``min_reclaim_bytes`` while
    keeping the largest tightest RPO margin.
    """
    objective_list = tuple(objectives)
    for objective in objective_list:
        if objective not in DEFAULT_OBJECTIVES:
            raise ValueError(f"unknown retention objective: {objective}")
    model = _Model(plan, records, artifacts, points, baseline_rpo)
    # A backup whose singleton deletion already violates a protection
    # constraint can never belong to a feasible deletion set (monotonicity).
    singleton_ok = [b for b in model.eligible if model.evaluate(frozenset({b}))[0]]
    infeasible = [b for b in model.eligible if b not in set(singleton_ok)]
    pinners = set(model.eligible) - set(singleton_ok)
    candidates: list[str] = []
    zero_yield: list[str] = []
    for backup_id in singleton_ok:
        # A backup whose files are all still required by an undeletable
        # verified backup can never release a byte; skip it in the search.
        if model.file_refs[model.records[backup_id].artifact_path] & pinners:
            zero_yield.append(backup_id)
        else:
            candidates.append(backup_id)
    report: dict[str, Any] = {
        "status": "ok", "reason": "", "max_candidates": max_candidates,
        "candidate_count": len(candidates), "candidates": candidates,
        "excluded": {"singleton_infeasible": infeasible, "zero_yield": zero_yield},
        "min_reclaim_bytes": min_reclaim_bytes,
    }
    if len(candidates) > max_candidates:
        report.update(
            status="over_limit",
            reason=(f"{len(candidates)} verified redundant candidate backups exceed the "
                    f"exact-computation limit of {max_candidates}; exact measurement is "
                    "refused instead of silently truncating."),
            capacity_upper_bound_bytes=model.released_bytes(frozenset(candidates)),
            plans=[],
        )
        return RetentionAssessment(report)
    best_bytes, best_margin = _search(model, tuple(candidates), min_reclaim_bytes)
    upper = best_bytes[1]
    plans: list[dict[str, Any]] = []
    for objective in objective_list:
        chosen, feasible, reason = best_bytes, True, ""
        if objective == OBJECTIVE_MAX_MIN_MARGIN:
            if best_margin is None:
                chosen, feasible = best_bytes, False
                reason = (
                    f"no deletion set releases at least {min_reclaim_bytes} bytes while "
                    "satisfying every protection constraint; at most "
                    f"{upper} bytes can be released"
                )
            else:
                chosen = best_margin
        plans.append(model.build_plan(objective, min_reclaim_bytes, chosen, feasible,
                                      reason, upper, catalog_path, catalog_hash))
    report.update(capacity_upper_bound_bytes=upper, plans=plans)
    return RetentionAssessment(report)
