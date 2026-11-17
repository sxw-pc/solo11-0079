"""Same-generation recovery evidence: five required offline scenarios."""

from __future__ import annotations

from pathlib import Path

from recovery_fixtures import D1, D2, ROW_COUNT, build_fixture, event, run


def _summary(bundle, drill="drill-demo-1"):
    return next(item for item in bundle.drills if item.drill_id == drill)


def _rto(bundle, drill="drill-demo-1"):
    return next(item for item in bundle.rto if item.drill_id == drill)


def _rules(bundle):
    return {item.rule_id: item for item in bundle.findings if item.object_id == "drill-demo-1"}


def _clean_retry_events(*, long: bool = False):
    """Recovery retry; old downstream checks carry gen-a, restore_base opened gen-b."""
    gap = 100 if long else 0

    def t(minute: int) -> str:
        return f"2026-11-09T{21 + minute // 60:02d}:{minute % 60:02d}:00Z"

    return [
        event("restore_base", 1, t(0), t(10), "failed", gen="gen-a", digest=D1),
        event("restore_base", 2, t(12 + gap), t(22 + gap), gen="gen-b", digest=D1),
        event("apply_incremental", 1, t(23 + gap), t(30 + gap), gen="gen-b", digest=D1),
        event("verify_rowcount", 1, t(5), t(8), rows=ROW_COUNT, gen="gen-a", digest=D1),
        event("verify_checksum", 1, t(8), t(9), sha=D1, gen="gen-a", digest=D1),
        event("publish_report", 1, t(9), t(10), gen="gen-a", digest=D1),
    ]


def test_verification_after_successful_recovery_passes(tmp_path: Path):
    events = [
        event("restore_base", 1, "2026-11-09T21:00:00Z", "2026-11-09T21:10:00Z",
              gen="gen-a", digest=D1),
        event("apply_incremental", 1, "2026-11-09T21:10:00Z", "2026-11-09T21:15:00Z",
              gen="gen-a", digest=D1),
        event("verify_rowcount", 1, "2026-11-09T21:15:00Z", "2026-11-09T21:18:00Z",
              rows=ROW_COUNT, gen="gen-a", digest=D1),
        event("verify_checksum", 1, "2026-11-09T21:18:00Z", "2026-11-09T21:20:00Z",
              sha=D1, gen="gen-a", digest=D1),
        event("publish_report", 1, "2026-11-09T21:20:00Z", "2026-11-09T21:22:00Z",
              gen="gen-a", digest=D1),
    ]
    root = build_fixture(tmp_path / "ok", events)
    bundle, report = run(root)
    summary = _summary(bundle)
    assert summary.status == "success" and summary.current_generation == "gen-a"
    assert _rto(bundle).status == "pass"
    assert {item.decision for item in bundle.drill_evidence} == {"adopted"}
    assert "EVID-010" not in _rules(bundle)
    assert report["drills"][0]["current_generation"] == "gen-a"


def test_retry_with_stale_evidence_is_inconclusive_under_strict_replay(tmp_path: Path):
    root = build_fixture(tmp_path / "stale", _clean_retry_events())
    bundle, report = run(root)
    summary = _summary(bundle)
    assert summary.status == "inconclusive"
    assert summary.current_generation == "gen-b" and summary.final_data_digest == D1
    rto = _rto(bundle)
    assert rto.status == "not_met" and not rto.successful
    rules = _rules(bundle)
    assert "EVID-011" in rules and "EVID-007" in rules
    decisions = {item.step: item.decision for item in bundle.drill_evidence}
    assert decisions == {step: "invalidated" for step in
                         ("verify_rowcount", "verify_checksum", "publish_report")}
    assert any(item["decision"] == "invalidated" for item in report["drill_evidence"])
    rto_report = report["objectives"]["rto"]
    assert not any(item["status"] == "success" for item in rto_report
                   if item["drill_id"] == "drill-demo-1")


def test_identical_digest_reuse_succeeds_only_under_reuse_policy(tmp_path: Path):
    events = _clean_retry_events()
    strict_root = build_fixture(tmp_path / "strict", events, policy="strict_replay")
    reuse_root = build_fixture(tmp_path / "reuse", events, policy="evidence_reuse")
    strict_bundle, _ = run(strict_root)
    reuse_bundle, reuse_report = run(reuse_root)
    assert _summary(strict_bundle).status == "inconclusive"
    assert _summary(reuse_bundle).status == "success"
    assert _rto(reuse_bundle).status == "pass"
    rules = {item.rule_id for item in reuse_bundle.findings
             if item.object_id == "drill-demo-1"}
    assert "EVID-012" in rules and "EVID-010" not in rules
    reused = [item for item in reuse_bundle.drill_evidence if item.decision == "reused"]
    assert {item.step for item in reused} == {
        "verify_rowcount", "verify_checksum", "publish_report"}
    assert all(item["reason"].startswith("identical full data digest")
               for item in reuse_report["drill_evidence"] if item["decision"] == "reused")


def test_different_digest_blocks_reuse_under_both_policies(tmp_path: Path):
    events = _clean_retry_events()
    for event_row in events:
        if event_row.get("recovery_generation") == "gen-b" and event_row["data_digest"] == D1:
            event_row["data_digest"] = D2
    for policy in ("strict_replay", "evidence_reuse"):
        root = build_fixture(tmp_path / policy, events, policy=policy, manifest_digest=D1)
        bundle, _ = run(root)
        assert _summary(bundle).status == "failed"
        assert _rto(bundle).status == "not_met"
        rules = _rules(bundle)
        assert "EVID-010" in rules and "EVID-012" not in rules
        assert all(item.decision == "invalidated" for item in bundle.drill_evidence)
        assert "CONS-005" in rules


def test_same_rowcount_alone_never_allows_reuse(tmp_path: Path):
    events = _clean_retry_events()
    for event_row in events:
        if event_row.get("recovery_generation") == "gen-b":
            event_row["data_digest"] = D2
        if event_row["step"] == "verify_rowcount":
            event_row["data_digest"] = None
    root = build_fixture(tmp_path / "rows-only", events, policy="evidence_reuse",
                         manifest_digest=D2)
    bundle, _ = run(root)
    assert _summary(bundle).status == "failed"
    rules = _rules(bundle)
    assert "EVID-010" in rules and "EVID-012" not in rules
    row = next(item for item in bundle.drill_evidence if item.step == "verify_rowcount")
    assert row.decision == "invalidated"


def test_valid_evidence_with_rto_timeout_breaches_rto(tmp_path: Path):
    events = _clean_retry_events(long=True)
    root = build_fixture(tmp_path / "timeout", events, policy="evidence_reuse",
                         rto_minutes=60)
    bundle, _ = run(root)
    rto = _rto(bundle)
    assert _summary(bundle).status == "success"
    assert rto.status == "breach" and rto.duration_minutes > 60
    assert rto.started_at == "2026-11-09T21:00:00Z"
    rule = _rules(bundle)["OBJ-RTO-001"]
    assert rule.evidence["duration_minutes"] == rto.duration_minutes
