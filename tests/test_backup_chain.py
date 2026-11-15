from __future__ import annotations

from datetime import datetime, timezone

from drillverify.backup_chain import assess_chains
from drillverify.records import ArtifactCheck, BackupRecord


def test_restorable_points_and_failure_rules(bundle):
    points = [item for item in bundle.points if item.dataset_id == "ds-orders"]
    assert len(points) == 40
    assert all(item.data_sha256 for item in points)
    rules = {(item.rule_id, item.object_id) for item in bundle.findings}
    assert ("CHAIN-004", "bk-events-017") in rules
    assert ("CHAIN-005", "bk-events-015") in rules
    assert ("CHAIN-006", "bk-events-016") in rules
    future = next(item for item in bundle.chains if item.backup_id == "bk-orders-901")
    assert not future.chain_complete and not future.restorable


def test_cycle_is_detected_deterministically(bundle):
    def record(backup_id: str, parent: str, hour: int) -> BackupRecord:
        started = datetime(2026, 11, 8, hour, tzinfo=timezone.utc)
        finished = datetime(2026, 11, 9, hour, tzinfo=timezone.utc)
        return BackupRecord(
            "ds-orders", backup_id, parent, "incremental", started, finished,
            f"artifacts/blobs/{backup_id}.bin", 10, "0" * 64, 1, "3", hour,
        )

    records = (record("bk-cycle-a", "bk-cycle-b", 1), record("bk-cycle-b", "bk-cycle-a", 2))
    checks = tuple(ArtifactCheck(item.backup_id, True, None, ()) for item in records)
    result = assess_chains(bundle.plan, records, checks, "catalog", "hash")
    assert all(not item.chain_complete for item in result.chains)
    assert sum(1 for item in result.findings if item.rule_id == "CHAIN-003") == 2
    assert all("CHAIN-003" in item.failure_rules for item in result.chains)


def test_chain_results_are_stably_sorted(bundle):
    keys = [(item.dataset_id, item.finished_at, item.backup_id) for item in bundle.chains]
    assert keys == sorted(keys)
    assert all(
        not item.restorable or (item.chain_complete and item.artifact_ready)
        for item in bundle.chains
    )
