from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

from drillverify.pipeline import run_pipeline
from drillverify.reporting import build_report, render_markdown
from drillverify.transaction_cohort import refines

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
ORDERS = "bk-orders-042"
EVENTS = "bk-events-014"
LEDGER = "bk-ledger-002"
COHORT = "cohort-close-1109"


def _row(part_id: str, masked: str, amount: int, role: str) -> dict:
    return {
        "part_id": part_id, "tx_ref_masked": masked, "amount": amount, "role": role,
        "source_fingerprint": hashlib.sha256(f"extract:{part_id}".encode()).hexdigest(),
    }


def _write_manifest(root: Path, backup_id: str, rows: list[dict]) -> None:
    path, payload = _edit_manifest(root, backup_id)
    payload["transaction_summary"] = {"rows": rows}
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _edit_manifest(root: Path, backup_id: str) -> tuple[Path, dict]:
    path = root / "artifacts" / f"manifest-{backup_id}.json"
    return path, json.loads(path.read_text(encoding="utf-8"))


def _repair_ledger(root: Path, rows: list[dict]) -> None:
    payload = b"synthetic ledger full backup blob\n"
    (root / "artifacts" / "blobs" / "bk-ledger-002.bin").write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    catalog = root / "catalog" / "backup_catalog.csv"
    lines = []
    for line in catalog.read_text(encoding="utf-8").splitlines():
        cols = line.split(",")
        if cols[:2] == ["ds-ledger", LEDGER]:
            cols[7], cols[8] = str(len(payload)), digest
        lines.append(",".join(cols))
    catalog.write_text("\n".join(lines) + "\n", encoding="utf-8")
    manifest = {
        "backup_id": LEDGER, "row_count": 800, "schema_version": "2",
        "data_sha256": hashlib.sha256(b"ledger restored data").hexdigest(),
        "transaction_summary": {"rows": rows},
    }
    (root / "artifacts" / f"manifest-{LEDGER}.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_spec(root: Path, *, purpose="strict_publish", members=None, budget=None) -> None:
    cohort = {
        "cohort_id": COHORT,
        "purpose": purpose,
        "members": members or [
            {"dataset_id": "ds-orders", "backup_id": ORDERS},
            {"dataset_id": "ds-events", "backup_id": EVENTS},
            {"dataset_id": "ds-ledger", "backup_id": LEDGER},
        ],
        "required_roles": ["order", "event", "debit", "credit"],
        "anchor_roles": ["debit", "credit"],
        "role_sources": {"order": ["ds-orders"], "event": ["ds-events"],
                         "debit": ["ds-ledger"], "credit": ["ds-ledger"]},
    }
    if budget is not None:
        cohort["search_budget"] = budget
    payload = {"schema_version": 1, "cohorts": [cohort]}
    (root / "plans" / "transaction_cohorts.yaml").write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8")


BASE_ORDERS = [_row("p-ord-1", "tx-**-**", 70, "order"), _row("p-ord-2", "tx-**-01", 30, "order")]
BASE_EVENTS = [_row("p-evt-1", "tx-**-01", 30, "event"), _row("p-evt-2", "tx-**-02", 70, "event")]
BASE_LEDGER = [
    _row("p-led-1", "tx-**-01", 30, "debit"), _row("p-led-2", "tx-**-01", 30, "credit"),
    _row("p-led-3", "tx-**-02", 70, "debit"), _row("p-led-4", "tx-**-02", 70, "credit"),
]


def _cohort_fixture(parent: Path, *, purpose="strict_publish", orders=None, events=None,
                    ledger=None, members=None, budget=None) -> Path:
    root = parent / "fixtures"
    shutil.copytree(FIXTURES, root)
    _write_manifest(root, ORDERS, BASE_ORDERS if orders is None else orders)
    _write_manifest(root, EVENTS, BASE_EVENTS if events is None else events)
    _repair_ledger(root, BASE_LEDGER if ledger is None else ledger)
    _write_spec(root, purpose=purpose, members=members, budget=budget)
    return root


def _cohort(bundle):
    (cohort,) = bundle.cohorts
    return cohort


def _txn_rules(bundle):
    return {f.rule_id for f in bundle.findings if f.object_id == COHORT}


def test_greedy_pairing_loses_where_global_proof_succeeds(tmp_path):
    root = _cohort_fixture(tmp_path)
    bundle = run_pipeline(root)
    cohort = _cohort(bundle)
    assert cohort.status == "proven_consistent"
    assert cohort.publish_gate == "released"
    assert cohort.evidence_basis == "transaction_summary"
    assert cohort.evidence_window_end == "2026-11-09T20:10:00Z"  # member points, not as_of
    proof = cohort.proof
    assert proof.min_gap == 0 and proof.max_gap == 0
    assert proof.assignments_evaluated == 1
    witness = dict(proof.min_witness.assignments)
    assert witness["p-ord-1"] == "tx-**-02" and witness["p-ord-2"] == "tx-**-01"
    assert len(witness) == 8  # every contribution matched exactly once
    # Greedy first-compatible pairing strands p-ord-2 and never closes tx-**-02.
    anchors = ["tx-**-01", "tx-**-02"]
    greedy = {part: next(a for a in anchors if refines(a, mask))
              for part, mask in (("p-ord-1", "tx-**-**"), ("p-ord-2", "tx-**-01"))}
    assert greedy == {"p-ord-1": "tx-**-01", "p-ord-2": "tx-**-01"}
    # Zip-by-row-number pairs the 70-order with the 30-event; equal totals mislead too.
    assert [70, 30] != [30, 70] and sum([70, 30]) == sum([30, 70])
    assert bundle.summary["transaction_cohorts"]["by_status"] == {"proven_consistent": 1}
    report = build_report(bundle)
    assert report["transaction_cohorts"][0]["status"] == "proven_consistent"
    assert "Transaction Cohort Consistency" in render_markdown(report)
    assert not _txn_rules(bundle)
    assert run_pipeline(root).run_id == bundle.run_id  # deterministic


def test_equal_totals_do_not_imply_per_transaction_conservation(tmp_path):
    root = _cohort_fixture(
        tmp_path,
        events=[_row("p-evt-1", "tx-**-01", 60, "event"), _row("p-evt-2", "tx-**-02", 40, "event")],
        ledger=[_row("p-led-1", "tx-**-01", 60, "debit"), _row("p-led-2", "tx-**-01", 60, "credit"),
                _row("p-led-3", "tx-**-02", 40, "debit"), _row("p-led-4", "tx-**-02", 40, "credit")],
    )
    bundle = run_pipeline(root)
    cohort = _cohort(bundle)
    # Cohort-wide role totals are equal (100 each) yet no legal attribution conserves.
    assert cohort.status == "proven_conflict"
    assert cohort.publish_gate == "paused"
    assert cohort.proof.min_gap == 60 and cohort.proof.max_gap == 60
    assert _txn_rules(bundle) == {"TXN-006"}


def _pending_rows():
    orders = BASE_ORDERS + [_row("p-ord-3", "tx-**-**", 10, "order")]
    events = BASE_EVENTS + [_row("p-evt-3", "tx-**-**", 10, "event")]
    ledger = BASE_LEDGER + [
        _row("p-led-5", "tx-**-**", 10, "debit"), _row("p-led-6", "tx-**-**", 10, "credit")]
    return orders, events, ledger


def test_mixed_interpretations_pause_strict_publish(tmp_path):
    orders, events, ledger = _pending_rows()
    bundle = run_pipeline(_cohort_fixture(tmp_path, orders=orders, events=events, ledger=ledger))
    cohort = _cohort(bundle)
    assert cohort.status == "pending_review"
    assert cohort.publish_gate == "paused"
    assert cohort.manual_verification_required
    assert cohort.proof.min_gap == 0 and cohort.proof.max_gap > 0
    assert cohort.proof.conserving_witnesses  # favorable candidates prove nothing
    assert {f.severity for f in bundle.findings if f.rule_id == "TXN-007"} == {"medium"}


def test_triage_review_lists_conserving_candidates_without_proving(tmp_path):
    orders, events, ledger = _pending_rows()
    root = _cohort_fixture(tmp_path, purpose="triage_review",
                           orders=orders, events=events, ledger=ledger)
    cohort = _cohort(run_pipeline(root))
    assert cohort.status == "pending_review"  # never auto-promoted by a favorable candidate
    assert cohort.publish_gate == "not_applicable"
    assert cohort.manual_verification_required
    assert cohort.proof.conserving_witnesses
    assert all(w.total_gap == 0 for w in cohort.proof.conserving_witnesses)


def test_split_parts_single_use_and_summation(tmp_path):
    events = [_row("p-evt-1", "tx-**-01", 50, "event"), _row("p-evt-2", "tx-**-02", 50, "event")]
    ledger = [_row("p-led-1", "tx-**-01", 50, "debit"), _row("p-led-2", "tx-**-01", 50, "credit"),
              _row("p-led-3", "tx-**-02", 50, "debit"), _row("p-led-4", "tx-**-02", 50, "credit")]
    # One 50-order part cannot cover both transactions: reuse is not permitted.
    root = _cohort_fixture(tmp_path / "single", orders=[_row("p-ord-1", "tx-**-**", 50, "order")],
                           events=events, ledger=ledger)
    bundle = run_pipeline(root)
    cohort = _cohort(bundle)
    assert (cohort.status, cohort.cause) == ("inconclusive", "no_legal_assignment")
    assert _txn_rules(bundle) == {"TXN-005"}
    # Two parts of one order sum correctly inside a single transaction.
    orders = [_row("p-ord-1a", "tx-**-01", 30, "order"), _row("p-ord-1b", "tx-**-01", 20, "order"),
              _row("p-ord-2", "tx-**-02", 50, "order")]
    cohort = _cohort(run_pipeline(_cohort_fixture(
        tmp_path / "split", orders=orders, events=events, ledger=ledger)))
    assert cohort.status == "proven_consistent"
    witness = dict(cohort.proof.min_witness.assignments)
    assert witness["p-ord-1a"] == witness["p-ord-1b"] == "tx-**-01"


def test_member_and_fingerprint_failures_are_locatable(tmp_path):
    members = [
        {"dataset_id": "ds-orders", "backup_id": ORDERS},
        {"dataset_id": "ds-events", "backup_id": EVENTS},
        {"dataset_id": "ds-ledger", "backup_id": "bk-ledger-003"},
    ]
    bundle = run_pipeline(_cohort_fixture(tmp_path / "unrestorable", members=members))
    cohort = _cohort(bundle)
    assert (cohort.status, cohort.cause) == ("inconclusive", "member_not_restorable")
    assert cohort.detail == "ds-ledger/bk-ledger-003" and _txn_rules(bundle) == {"TXN-002"}
    members[2] = {"dataset_id": "ds-ledger", "backup_id": "bk-ledger-404"}
    cohort = _cohort(run_pipeline(_cohort_fixture(tmp_path / "unknown", members=members)))
    assert cohort.cause == "missing_member"


def test_manifest_fingerprint_pinning(tmp_path):
    root = _cohort_fixture(tmp_path)
    hashes = {b: hashlib.sha256((root / "artifacts" / f"manifest-{b}.json").read_bytes()).hexdigest()
              for b in (ORDERS, EVENTS, LEDGER)}
    members = [
        {"dataset_id": ds, "backup_id": b, "expected_manifest_sha256": hashes[b]}
        for ds, b in (("ds-orders", ORDERS), ("ds-events", EVENTS), ("ds-ledger", LEDGER))
    ]
    _write_spec(root, members=members)
    assert _cohort(run_pipeline(root)).status == "proven_consistent"
    members[0] = dict(members[0], expected_manifest_sha256="0" * 64)
    _write_spec(root, members=members)
    bundle = run_pipeline(root)
    cohort = _cohort(bundle)
    assert (cohort.status, cohort.cause) == ("inconclusive", "fingerprint_mismatch")
    assert cohort.detail == "ds-orders/" + ORDERS and _txn_rules(bundle) == {"TXN-003"}


def test_search_budget_exhaustion_is_reported(tmp_path):
    bundle = run_pipeline(_cohort_fixture(tmp_path, budget=1))
    cohort = _cohort(bundle)
    assert (cohort.status, cohort.cause) == ("inconclusive", "budget_exceeded")
    assert cohort.proof.budget == 1 and _txn_rules(bundle) == {"TXN-008"}


def test_missing_malformed_and_duplicate_summary(tmp_path):
    root = _cohort_fixture(tmp_path / "missing")
    path, payload = _edit_manifest(root, ORDERS)
    payload.pop("transaction_summary", None)  # no summary section at all
    path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    bundle = run_pipeline(root)
    cohort = _cohort(bundle)
    assert (cohort.status, cohort.cause) == ("inconclusive", "missing_summary")
    assert _txn_rules(bundle) == {"TXN-004"}
    root = _cohort_fixture(tmp_path / "malformed")
    path, payload = _edit_manifest(root, ORDERS)
    payload["transaction_summary"] = {"rows": [{"part_id": "x"}]}
    path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    bundle = run_pipeline(root)
    cohort = _cohort(bundle)
    assert (cohort.status, cohort.cause) == ("inconclusive", "invalid_summary")
    assert _txn_rules(bundle) == {"TXN-004"}
    assert any(f.rule_id == "ART-007" for f in bundle.findings)
    duplicate = [_row("p-ord-1", "tx-**-01", 30, "order"), _row("p-ord-1", "tx-**-02", 70, "order")]
    cohort = _cohort(run_pipeline(_cohort_fixture(tmp_path / "duplicate", orders=duplicate)))
    assert cohort.cause == "invalid_summary" and "p-ord-1" in cohort.detail


def test_summary_changes_causally_change_verdict_and_report(tmp_path):
    base = run_pipeline(_cohort_fixture(tmp_path / "base"))
    changed_orders = [_row("p-ord-1", "tx-**-**", 71, "order"), _row("p-ord-2", "tx-**-01", 30, "order")]
    changed = run_pipeline(_cohort_fixture(tmp_path / "changed", orders=changed_orders))
    assert _cohort(base).status == "proven_consistent"
    assert _cohort(changed).status == "proven_conflict"
    assert _cohort(changed).proof.min_gap == 1
    assert base.run_id != changed.run_id
    reports = [build_report(b)["transaction_cohorts"][0]["status"] for b in (base, changed)]
    assert reports == ["proven_consistent", "proven_conflict"]
    # An attribution (mask) change reshapes the same feasibility domain.
    remasked_orders = [_row("p-ord-1", "tx-**-**", 70, "order"), _row("p-ord-2", "tx-**-02", 30, "order")]
    remasked = _cohort(run_pipeline(_cohort_fixture(tmp_path / "remasked", orders=remasked_orders)))
    assert remasked.status == "proven_conflict" and remasked.proof.max_gap == 80


def test_invalid_spec_is_an_error_finding(tmp_path):
    bundle = run_pipeline(_cohort_fixture(tmp_path, purpose="publish_hard"))
    assert bundle.cohorts == ()
    assert any(f.rule_id == "TXN-001" and f.severity == "error" for f in bundle.findings)

def test_mask_refinement_rules():
    assert refines("tx-**-01", "tx-**-**") and refines("tx-**-01", "tx-**-01")
    assert not refines("tx-**-**", "tx-**-01") and not refines("tx-**-02", "tx-**-01")
    assert not refines("tx-**-011", "tx-**-01")


def test_fixture_without_cohort_spec_keeps_legacy_behavior(bundle, report):
    assert bundle.cohorts == ()
    assert "transaction_cohorts" not in report
    assert "transaction_cohorts" not in report["summary"]
    assert bundle.run_id == "ea64dfaf846ec4d7"
