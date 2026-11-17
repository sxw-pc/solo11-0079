from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from drillverify.backup_chain import assess_chains
from drillverify.models import DatasetConfig, RecoveryPlan
from drillverify.objectives import evaluate_rpo
from drillverify.pipeline import run_pipeline
from drillverify.records import ArtifactCheck, ArtifactManifest, BackupRecord
from drillverify.reporting import render_markdown
from drillverify.retention import assess_retention

AS_OF = datetime(2026, 11, 10, 0, 0, tzinfo=timezone.utc)


def make_plan(rpo_minutes: int, dataset_id: str = "ds-a") -> RecoveryPlan:
    dataset = DatasetConfig(
        dataset_id, dataset_id, rpo_minutes, 60, (), False, False, "team-a", "sun:02", "artifacts"
    )
    return RecoveryPlan(AS_OF, 1, (dataset,), "plans/recovery_plan.yaml")


def make_record(backup_id, minutes_ago, size, *, dataset_id="ds-a", parent=None,
                backup_type="full", path=None, sha=None) -> BackupRecord:
    finished = AS_OF - timedelta(minutes=minutes_ago)
    return BackupRecord(
        dataset_id, backup_id, parent, backup_type, finished - timedelta(minutes=5), finished,
        path or f"artifacts/{backup_id}.bin", size,
        sha or hashlib.sha256(backup_id.encode()).hexdigest(), 100, "3", 1,
    )


def make_checks(records) -> tuple[ArtifactCheck, ...]:
    return tuple(
        ArtifactCheck(
            item.backup_id, True,
            ArtifactManifest(item.backup_id, item.row_count,
                             hashlib.sha256(f"{item.backup_id}-d".encode()).hexdigest(),
                             item.schema_version, f"artifacts/manifest-{item.backup_id}.json"),
            (),
        )
        for item in records
    )


def run_retention(plan, records, checks, *, min_reclaim_bytes=0):
    points = assess_chains(plan, records, checks, "catalog/catalog.csv", "cathash").points
    rpo, _ = evaluate_rpo(plan, points, "catalog/catalog.csv", "cathash")
    assessment = assess_retention(
        plan, records, checks, points, rpo, min_reclaim_bytes=min_reclaim_bytes,
        catalog_path="catalog/catalog.csv", catalog_hash="cathash",
    )
    return assessment.to_dict()


def divergence_scenario():
    # Old full chain vs independent increments; combined deletion breaches.
    shared_sha = hashlib.sha256(b"shared-artifact").hexdigest()
    records = (
        make_record("bk-full-shared", 301, 10, path="artifacts/shared.bin", sha=shared_sha),
        make_record("bk-full-new", 249, 10, path="artifacts/shared.bin", sha=shared_sha),
        make_record("bk-full-old", 200, 40),
        make_record("bk-inc-new-1", 150, 30, parent="bk-full-new", backup_type="incremental"),
        make_record("bk-inc-old-1", 108, 30, parent="bk-full-old", backup_type="incremental"),
        make_record("bk-inc-new-2", 99, 30, parent="bk-inc-new-1", backup_type="incremental"),
        make_record("bk-inc-old-2", 50, 30, parent="bk-inc-old-1", backup_type="incremental"),
    )
    return make_plan(100), records, make_checks(records)


def plans(assessment):
    return {plan["objective"]: plan for plan in assessment["plans"]}


def test_objectives_diverge_on_shared_directory():
    plan, records, checks = divergence_scenario()
    assessment = run_retention(plan, records, checks, min_reclaim_bytes=50)
    assert assessment["status"] == "ok" and assessment["candidate_count"] == 5
    assert set(assessment["candidates"]) == {
        "bk-full-old", "bk-inc-old-1", "bk-inc-old-2", "bk-inc-new-1", "bk-inc-new-2"}
    # Deleting bk-full-new would orphan the newer increments and breach RPO.
    assert assessment["excluded"]["singleton_infeasible"] == ["bk-full-new"]
    # bk-full-shared only references a file that bk-full-new still needs.
    assert assessment["excluded"]["zero_yield"] == ["bk-full-shared"]

    capacity, margin = plans(assessment)["max_bytes"], plans(assessment)["max_min_margin"]
    assert capacity["feasible"] and margin["feasible"]
    # Capacity objective: delete the old full chain, release 100 bytes, margin 1.
    assert {d["backup_id"] for d in capacity["deletions"]} == {
        "bk-full-old", "bk-inc-old-1", "bk-inc-old-2",
    }
    assert capacity["total_reclaimable_bytes"] == 100
    assert capacity["tightest_margin_minutes"] == 1
    # Margin objective with S=50: keep the 8-minute margin, release 60 bytes.
    assert {d["backup_id"] for d in margin["deletions"]} == {"bk-inc-new-1", "bk-inc-new-2"}
    assert margin["total_reclaimable_bytes"] == 60
    assert margin["tightest_margin_minutes"] == 8

    full_old = next(d for d in capacity["deletions"] if d["backup_id"] == "bk-full-old")
    assert full_old["artifact_path"] == "artifacts/bk-full-old.bin"
    assert full_old["input_sha256"] == hashlib.sha256(b"bk-full-old").hexdigest()
    assert full_old["affected_descendants"] == ["bk-inc-old-1", "bk-inc-old-2"]

    dataset, margin_dataset = capacity["datasets"][0], margin["datasets"][0]
    assert dataset["baseline_status"] == dataset["status"] == "pass"
    assert dataset["compliant_after"]
    assert set(dataset["retained_points"]) == {
        "bk-full-shared", "bk-full-new", "bk-inc-new-1", "bk-inc-new-2"}
    assert (dataset["max_gap_minutes"], dataset["margin_minutes"]) == (99, 1)
    assert (margin_dataset["max_gap_minutes"], margin_dataset["margin_minutes"]) == (92, 8)

    released = {item["path"]: item for item in capacity["capacity_proof"]["released_files"]}
    assert set(released) == {
        "artifacts/bk-full-old.bin", "artifacts/bk-inc-old-1.bin", "artifacts/bk-inc-old-2.bin"}
    assert sum(item["size_bytes"] for item in released.values()) == 100
    assert all(item["sha256"] for item in released.values())
    assert capacity["capacity_upper_bound_bytes"] == 100
    assert assessment["simulation"] and assessment["requires_human_review"]
    assert assessment["executed"] is False
    assert capacity["simulation"] and capacity["requires_human_review"]


def test_ancestor_break_invalidates_descendant_chains():
    plan, records, checks = divergence_scenario()
    remaining = tuple(item for item in records if item.backup_id != "bk-full-old")
    remaining_checks = tuple(item for item in checks if item.backup_id != "bk-full-old")
    chains = assess_chains(plan, remaining, remaining_checks, "catalog", "hash")
    status = {item.backup_id: item for item in chains.chains}
    assert not status["bk-inc-old-1"].restorable
    assert "CHAIN-001" in status["bk-inc-old-1"].failure_rules
    assert not status["bk-inc-old-2"].restorable
    assert "CHAIN-009" in status["bk-inc-old-2"].failure_rules
    assert status["bk-inc-new-2"].restorable


def test_adjacent_and_final_gaps_are_recomputed():
    plan = make_plan(120)
    records = (
        make_record("bk-first", 200, 10),
        make_record("bk-mid", 100, 10),
        make_record("bk-last", 40, 10),
    )
    assessment = run_retention(plan, records, make_checks(records))
    # Removing the middle point merges the adjacent gaps to 160 > 120.
    assert assessment["excluded"]["singleton_infeasible"] == ["bk-mid"]
    assert set(assessment["candidates"]) == {"bk-first", "bk-last"}
    capacity = plans(assessment)["max_bytes"]
    assert {d["backup_id"] for d in capacity["deletions"]} == {"bk-first", "bk-last"}
    dataset = capacity["datasets"][0]
    # Only bk-mid remains: the binding gap is the final gap to as_of.
    assert dataset["retained_points"] == ["bk-mid"]
    assert dataset["max_gap_minutes"] == dataset["minutes_since_last_point"] == 100
    assert dataset["margin_minutes"] == 20


def test_file_alias_capacity_is_deduplicated_per_physical_file():
    plan = make_plan(140)
    shared_sha = hashlib.sha256(b"alias-target").hexdigest()
    pinned_sha = hashlib.sha256(b"pinned-target").hexdigest()
    records = (
        make_record("bk-a1", 200, 50, path="artifacts/shared.bin", sha=shared_sha),
        make_record("bk-a2", 200, 50, path="artifacts/shared.bin", sha=shared_sha),
        make_record("bk-c", 150, 30, path="artifacts/pinned.bin", sha=pinned_sha),
        make_record("bk-b", 100, 30, path="artifacts/pinned.bin", sha=pinned_sha),
    )
    assessment = run_retention(plan, records, make_checks(records))
    # bk-b is the newest point; deleting it leaves a 150-minute final gap.
    assert assessment["excluded"]["singleton_infeasible"] == ["bk-b"]
    # bk-c's only file is still required by pinned bk-b: zero reclaimable yield.
    assert assessment["excluded"]["zero_yield"] == ["bk-c"]
    assert set(assessment["candidates"]) == {"bk-a1", "bk-a2"}

    capacity = plans(assessment)["max_bytes"]
    assert {d["backup_id"] for d in capacity["deletions"]} == {"bk-a1", "bk-a2"}
    # The shared physical file is counted once, not once per referencing backup.
    assert capacity["total_reclaimable_bytes"] == 50
    released = capacity["capacity_proof"]["released_files"]
    assert [item["path"] for item in released] == ["artifacts/shared.bin"]
    assert released[0]["size_bytes"] == 50
    assert set(released[0]["referenced_by"]) == {"bk-a1", "bk-a2"}
    # pinned.bin is never released: a retained backup still needs it.
    assert all(item["path"] != "artifacts/pinned.bin" for item in released)


def test_lexicographic_tie_break_is_deterministic():
    plan = make_plan(300)
    records = (make_record("bk-a1", 300, 50), make_record("bk-a2", 300, 50))
    first = run_retention(plan, records, make_checks(records))
    capacity = plans(first)["max_bytes"]
    # Equivalent singleton deletions: the lexicographically smallest id wins.
    assert [d["backup_id"] for d in capacity["deletions"]] == ["bk-a1"]
    assert capacity["total_reclaimable_bytes"] == 50
    reversed_records = tuple(reversed(records))
    second = run_retention(plan, reversed_records, make_checks(reversed_records))
    assert second == first


def test_infeasible_margin_reports_reason_and_capacity_upper_bound():
    plan, records, checks = divergence_scenario()
    assessment = run_retention(plan, records, checks, min_reclaim_bytes=101)
    margin = plans(assessment)["max_min_margin"]
    assert not margin["feasible"]
    assert "101" in margin["reason"]
    assert margin["capacity_upper_bound_bytes"] == 100
    assert margin["deletions"] == [] and margin["total_reclaimable_bytes"] == 0
    assert plans(assessment)["max_bytes"]["total_reclaimable_bytes"] == 100


def test_no_redundancy_means_no_feasible_release():
    plan = make_plan(120)
    records = (make_record("bk-only", 100, 25),)
    assessment = run_retention(plan, records, make_checks(records), min_reclaim_bytes=1)
    assert assessment["status"] == "ok" and assessment["candidate_count"] == 0
    capacity, margin = plans(assessment)["max_bytes"], plans(assessment)["max_min_margin"]
    assert capacity["feasible"] and capacity["deletions"] == []
    assert capacity["total_reclaimable_bytes"] == 0
    assert not margin["feasible"] and margin["capacity_upper_bound_bytes"] == 0


def test_non_compliant_dataset_is_never_reported_compliant():
    plan = make_plan(300, dataset_id="ds-b")
    records = (
        make_record("bk-b1", 500, 40, dataset_id="ds-b"),
        make_record("bk-b2", 100, 40, dataset_id="ds-b"),
        make_record("bk-broken", 50, 25, dataset_id="ds-b",
                    parent="bk-missing", backup_type="incremental"),
        make_record("bk-bad", 60, 15, dataset_id="ds-b"),
    )
    checks = list(make_checks(records[:3]))
    checks.append(ArtifactCheck("bk-bad", False, None, ("ART-005",)))
    assessment = run_retention(plan, records, tuple(checks))
    # Baseline breach (400 > 300): no restorable point of ds-b may be lost.
    assert assessment["excluded"]["singleton_infeasible"] == ["bk-b1", "bk-b2"]
    # A verified but non-restorable backup is reclaimable dead weight.
    assert assessment["candidates"] == ["bk-broken"]
    # An unverified artifact is never modelled.
    assert "bk-bad" not in assessment["candidates"]

    capacity = plans(assessment)["max_bytes"]
    assert [d["backup_id"] for d in capacity["deletions"]] == ["bk-broken"]
    assert capacity["total_reclaimable_bytes"] == 25
    dataset = capacity["datasets"][0]
    assert dataset["baseline_status"] == dataset["status"] == "breach"
    assert not dataset["compliant_after"]
    assert dataset["note"] == "pre_existing_non_compliance"
    assert dataset["retained_points"] == ["bk-b1", "bk-b2"]
    released = capacity["capacity_proof"]["released_files"]
    assert all(item["path"] != "artifacts/bk-bad.bin" for item in released)


def test_candidate_limit_returns_over_limit_without_truncating():
    plan = make_plan(2000)
    records = tuple(make_record(f"bk-{i:02d}", 80 * (i + 1), 10) for i in range(17))
    assessment = run_retention(plan, records, make_checks(records))
    assert assessment["status"] == "over_limit"
    assert assessment["candidate_count"] == 17
    assert "16" in assessment["reason"]
    assert assessment["plans"] == []
    # Safe upper bound: deleting every candidate releases at most all files.
    assert assessment["capacity_upper_bound_bytes"] == 170


def test_shuffled_inputs_produce_identical_assessment():
    plan, records, checks = divergence_scenario()
    baseline = run_retention(plan, records, checks, min_reclaim_bytes=50)
    order = [3, 0, 6, 1, 5, 2, 4]
    shuffled_records = tuple(records[i] for i in order)
    shuffled_checks = tuple(checks[i] for i in order)
    shuffled = run_retention(plan, shuffled_records, shuffled_checks, min_reclaim_bytes=50)
    assert json.dumps(shuffled, sort_keys=True) == json.dumps(baseline, sort_keys=True)


def test_simulation_never_modifies_original_files(fixture_copy: Path):
    def snapshot(root: Path) -> dict[str, str]:
        return {
            path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("*")) if path.is_file()
        }

    before = snapshot(fixture_copy)
    bundle = run_pipeline(fixture_copy)
    assert bundle.retention.plans is not None
    assert snapshot(fixture_copy) == before


def test_pipeline_attaches_conditional_retention(bundle, report):
    retention = bundle.retention
    assert retention.status in {"ok", "over_limit"}
    assert retention.simulation and retention.requires_human_review
    section = report["retention"]
    assert section["simulation"] is True
    assert section["requires_human_review"] is True
    assert section["executed"] is False
    assert isinstance(section["plans"], list)
    markdown = render_markdown(report)
    assert "Retention Simulation" in markdown
    assert "requires human review" in markdown
