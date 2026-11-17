"""Storage chargeback: physical union billing and authorized team contracts."""
from __future__ import annotations
import hashlib
import json
from decimal import Decimal
from fractions import Fraction
from pathlib import Path
import yaml
from drillverify.chargeback import invoice_for, tiered_cost
from drillverify.models import PricingStep, TierPricing
from drillverify.pipeline import run_pipeline
from drillverify.reporting import build_report, render_html, render_markdown
MB = 1_000_000
LADDER = {"min_fee": 0, "steps": [{"up_to_mb": 10, "per_mb": 2}, {"per_mb": 1}]}
def make_fixture(root: Path, spec: dict) -> Path:
    plan = {
        "as_of": "2026-11-10T00:00:00Z",
        "analysis_window_days": 7,
        "datasets": [
            {"dataset_id": ds, "display_name": ds, "rpo_minutes": 525600, "rto_minutes": 525600,
             "required_steps": ["precheck"], "checksum_required": False, "rowcount_required": False,
             "owner_team": owner, "maintenance_window": "sun:02:00-04:00Z", "artifact_manifest_path": "artifacts"}
            for ds, owner in spec["teams"].items()
        ],
    }
    if spec.get("pricing") is not None:
        plan["chargeback"] = {"inventory_path": "storage/inventory.json", "pricing": spec["pricing"]}
        plan["chargeback"].update(spec.get("chargeback", {}))
    (root / "plans").mkdir(parents=True)
    (root / "plans" / "recovery_plan.yaml").write_text(yaml.safe_dump(plan), encoding="utf-8")
    (root / "logs").mkdir()
    (root / "logs" / "restore_drill.jsonl").write_text("", encoding="utf-8")
    blobs = root / "artifacts" / "blobs"
    blobs.mkdir(parents=True)
    rows = ["dataset_id,backup_id,parent_backup_id,backup_type,started_at,finished_at,"
            "artifact_path,artifact_size_bytes,sha256,row_count,schema_version"]
    for item in spec.get("backups", []):
        payload = bytes([item.get("fill", 7)]) * item["size"]
        digest = hashlib.sha256(payload).hexdigest()
        (blobs / f"{item['backup_id']}.bin").write_bytes(payload)
        rows.append(f"{item['dataset_id']},{item['backup_id']},,full,{item.get('started', '2026-11-05T00:00:00Z')},"
                    f"{item.get('finished', '2026-11-05T01:00:00Z')},"
                    f"artifacts/blobs/{item['backup_id']}.bin,{item['size']},{digest},10,1")
        manifest = {"backup_id": item["backup_id"], "row_count": 10, "data_sha256": digest, "schema_version": "1"}
        (blobs.parent / f"manifest-{item['backup_id']}.json").write_text(json.dumps(manifest), encoding="utf-8")
    (root / "catalog").mkdir()
    (root / "catalog" / "backup_catalog.csv").write_text("\n".join(rows) + "\n", encoding="utf-8")
    if spec.get("blocks") is not None:
        objects = root / "storage" / "objects"
        objects.mkdir(parents=True)
        entries = []
        for block in spec["blocks"]:
            payload = bytes([block.get("fill", 3)]) * block["size"]
            (objects / f"{block['block_id']}.bin").write_bytes(payload)
            entries.append({"block_id": block["block_id"], "sha256": hashlib.sha256(payload).hexdigest(),
                            "size_bytes": block["size"], "tier": block.get("tier", "hot"),
                            "object_path": f"storage/objects/{block['block_id']}.bin",
                            "primary_team": block["primary_team"]})
        artifacts = {}
        for backup_id, parts in spec.get("refs", {}).items():
            offset = 0
            artifacts[backup_id] = []
            for block_id, length in parts:
                artifacts[backup_id].append({"block_id": block_id, "offset_bytes": offset, "length_bytes": length})
                offset += length
        (root / "storage" / "inventory.json").write_text(
            json.dumps({"blocks": entries, "artifacts": artifacts}), encoding="utf-8")
    return root
def counterexample(root: Path, **overrides) -> Path:
    spec = {
        "teams": {"ds-a": "team-a", "ds-b": "team-b"},
        "pricing": {"default": LADDER},
        "backups": [
            {"backup_id": "bk-a1", "dataset_id": "ds-a", "size": 14 * MB},
            {"backup_id": "bk-b1", "dataset_id": "ds-b", "size": 9 * MB},
        ],
        "blocks": [
            {"block_id": "blk-01-shared", "size": 8 * MB, "primary_team": "team-a"},
            {"block_id": "blk-02-a", "size": 6 * MB, "primary_team": "team-a"},
            {"block_id": "blk-03-b", "size": 1 * MB, "primary_team": "team-b"},
        ],
        "refs": {
            "bk-a1": [("blk-01-shared", 8 * MB), ("blk-02-a", 6 * MB)],
            "bk-b1": [("blk-01-shared", 8 * MB), ("blk-03-b", 1 * MB)],
        },
    }
    spec.update(overrides)
    return make_fixture(root, spec)
def amounts(contract) -> dict:
    return {charge.team: charge.amount for charge in contract.teams}
def test_counterexample_two_contracts_one_bill(tmp_path):
    chargeback = run_pipeline(counterexample(tmp_path)).chargeback
    assert chargeback.status == "settled"
    assert chargeback.logical_bytes == 23 * MB  # naive per-team sum double-counts the shared block
    (bucket,) = chargeback.buckets
    assert bucket.union_bytes == 15 * MB and bucket.invoice == Decimal(25)
    assert chargeback.total_invoice == Decimal(25)
    primary, shapley = chargeback.contracts
    assert amounts(primary) == {"team-a": Fraction(24), "team-b": Fraction(1)}
    assert amounts(shapley) == {"team-a": Fraction(31, 2), "team-b": Fraction(19, 2)}
    for contract in (primary, shapley):
        assert contract.total == sum(amounts(contract).values()) == Fraction(25)
        assert all(amount >= 0 for amount in amounts(contract).values())
    witnesses = {w["block_id"] for charge in primary.teams for w in charge.witnesses}
    assert witnesses == {"blk-01-shared", "blk-02-a", "blk-03-b"}
    assert all(charge.witnesses for charge in shapley.teams)
    proportional = {Fraction(25 * 14, 23), Fraction(25 * 9, 23)}  # dedup-then-prorate is neither contract
    assert not proportional & set(amounts(primary).values())
    assert not proportional & set(amounts(shapley).values())
    doc = chargeback.to_dict()
    assert {c["team"]: c["amount"] for c in doc["contracts"][1]["teams"]} == {"team-a": "15.5", "team-b": "9.5"}
def test_tier_boundary_and_min_fee_are_exact():
    ladder = TierPricing((PricingStep(Decimal(10), Decimal(2)), PricingStep(None, Decimal(1))), Decimal(0))
    assert invoice_for(0, ladder) == 0
    assert tiered_cost(10 * MB, ladder) == Decimal(20)
    assert invoice_for(10 * MB + 1, ladder) == Decimal("20.000001")
    assert tiered_cost(15 * MB, ladder) == Decimal(25)
    assert invoice_for(MB, TierPricing(ladder.steps, Decimal(5))) == Decimal(5)
    assert invoice_for(0, TierPricing(ladder.steps, Decimal(5))) == 0
def test_min_fee_settles_and_balances(tmp_path):
    root = make_fixture(tmp_path, {
        "teams": {"ds-a": "team-a"}, "pricing": {"default": {"min_fee": 5, "steps": [{"per_mb": 1}]}},
        "backups": [{"backup_id": "bk-a1", "dataset_id": "ds-a", "size": MB}],
        "blocks": [{"block_id": "blk-01", "size": MB, "primary_team": "team-a"}],
        "refs": {"bk-a1": [("blk-01", MB)]},
    })
    chargeback = run_pipeline(root).chargeback
    assert chargeback.total_invoice == Decimal(5)
    primary, shapley = chargeback.contracts
    assert amounts(primary) == amounts(shapley) == {"team-a": Fraction(5)}
    assert primary.teams[0].witnesses[0]["marginal"] == "5"
def test_conflicting_block_id_unproves_bill(tmp_path):
    root = counterexample(tmp_path)
    inventory_path = root / "storage" / "inventory.json"
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    inventory["blocks"].append(dict(inventory["blocks"][0], size_bytes=999))
    inventory_path.write_text(json.dumps(inventory), encoding="utf-8")
    chargeback = run_pipeline(root).chargeback
    assert chargeback.status == "unproven"
    assert chargeback.buckets is None and chargeback.total_invoice is None and chargeback.contracts == ()
    assert "BILL-003" in {finding.rule_id for finding in chargeback.findings}
    assert chargeback.logical_bytes == 23 * MB  # logical usage is still shown
def test_missing_blocks_unprove_bill_not_zero(tmp_path):
    root = counterexample(tmp_path / "a")
    inventory_path = root / "storage" / "inventory.json"
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    del inventory["artifacts"]["bk-b1"]  # a verified artifact loses its declared coverage
    inventory_path.write_text(json.dumps(inventory), encoding="utf-8")
    chargeback = run_pipeline(root).chargeback
    assert chargeback.status == "unproven" and chargeback.total_invoice is None
    assert any(f.rule_id == "BILL-006" and f.object_id == "bk-b1" for f in chargeback.findings)
    root = counterexample(tmp_path / "b")
    (root / "storage" / "objects" / "blk-03-b.bin").unlink()
    chargeback = run_pipeline(root).chargeback
    assert chargeback.status == "unproven" and chargeback.total_invoice is None
    assert any(f.rule_id == "BILL-004" and f.object_id == "blk-03-b" for f in chargeback.findings)
def test_tampered_block_object_unproves_bill(tmp_path):
    root = counterexample(tmp_path)
    blob = root / "storage" / "objects" / "blk-02-a.bin"
    blob.write_bytes(blob.read_bytes() + b"x")
    chargeback = run_pipeline(root).chargeback
    assert chargeback.status == "unproven"
    assert any(f.rule_id == "BILL-005" and f.object_id == "blk-02-a" for f in chargeback.findings)
def test_same_digest_does_not_imply_dedup(tmp_path):
    root = make_fixture(tmp_path, {
        "teams": {"ds-a": "team-a"}, "pricing": {"default": LADDER},
        "backups": [{"backup_id": "bk-a1", "dataset_id": "ds-a", "size": 4 * MB}],
        "blocks": [{"block_id": "blk-01", "size": 2 * MB, "primary_team": "team-a"},
                   {"block_id": "blk-02", "size": 2 * MB, "primary_team": "team-a"}],
        "refs": {"bk-a1": [("blk-01", 2 * MB), ("blk-02", 2 * MB)]},
    })
    chargeback = run_pipeline(root).chargeback
    assert chargeback.buckets[0].union_bytes == 4 * MB  # identical content, distinct ids: billed twice
    assert chargeback.total_invoice == Decimal(8)
def test_three_team_shapley_is_symmetric(tmp_path):
    root = make_fixture(tmp_path, {
        "teams": {f"ds-{x}": f"team-{x}" for x in "abc"}, "pricing": {"default": LADDER},
        "backups": [{"backup_id": f"bk-{x}1", "dataset_id": f"ds-{x}", "size": 8 * MB} for x in "abc"],
        "blocks": [{"block_id": "blk-shared", "size": 8 * MB, "primary_team": "team-a"}],
        "refs": {f"bk-{x}1": [("blk-shared", 8 * MB)] for x in "abc"},
    })
    chargeback = run_pipeline(root).chargeback
    assert chargeback.total_invoice == Decimal(16)
    primary, shapley = chargeback.contracts
    assert amounts(primary) == {"team-a": Fraction(16), "team-b": Fraction(0), "team-c": Fraction(0)}
    assert amounts(shapley) == {f"team-{x}": Fraction(16, 3) for x in "abc"}
    assert sum(amounts(shapley).values()) == Fraction(16)
    assert chargeback.to_dict()["contracts"][1]["teams"][0]["amount"] == "16/3"
def test_shapley_limit_declines_without_pseudo_precision(tmp_path):
    root = make_fixture(tmp_path, {
        "teams": {f"ds-t{i}": f"team-t{i}" for i in range(9)}, "pricing": {"default": LADDER},
        "backups": [{"backup_id": f"bk-t{i}", "dataset_id": f"ds-t{i}", "size": MB} for i in range(9)],
        "blocks": [{"block_id": f"blk-t{i}", "size": MB, "primary_team": f"team-t{i}"} for i in range(9)],
        "refs": {f"bk-t{i}": [(f"blk-t{i}", MB)] for i in range(9)},
    })
    chargeback = run_pipeline(root).chargeback
    assert chargeback.status == "settled"
    primary, shapley = chargeback.contracts
    assert primary.status == "settled" and primary.total == Fraction(18)
    assert shapley.status == "unavailable" and shapley.total is None and shapley.teams == ()
    assert any(f.rule_id == "BILL-008" for f in chargeback.findings)
def test_subset_budget_is_enforced(tmp_path):
    root = make_fixture(tmp_path, {
        "teams": {f"ds-{x}": f"team-{x}" for x in "abc"}, "pricing": {"default": LADDER},
        "chargeback": {"max_subsets": 4},
        "backups": [{"backup_id": f"bk-{x}1", "dataset_id": f"ds-{x}", "size": 8 * MB} for x in "abc"],
        "blocks": [{"block_id": "blk-shared", "size": 8 * MB, "primary_team": "team-a"}],
        "refs": {f"bk-{x}1": [("blk-shared", 8 * MB)] for x in "abc"},
    })
    contracts = run_pipeline(root).chargeback.contracts
    assert contracts[0].status == "settled" and contracts[1].status == "unavailable"
def test_union_is_per_billing_period(tmp_path):
    root = make_fixture(tmp_path, {
        "teams": {"ds-a": "team-a"}, "pricing": {"default": LADDER},
        "backups": [{"backup_id": "bk-a1", "dataset_id": "ds-a", "size": 8 * MB},
                    {"backup_id": "bk-a2", "dataset_id": "ds-a", "size": 8 * MB,
                     "started": "2026-10-05T00:00:00Z", "finished": "2026-10-05T01:00:00Z"}],
        "blocks": [{"block_id": "blk-shared", "size": 8 * MB, "primary_team": "team-a"}],
        "refs": {"bk-a1": [("blk-shared", 8 * MB)], "bk-a2": [("blk-shared", 8 * MB)]},
    })
    chargeback = run_pipeline(root).chargeback
    assert {b.period: b.invoice for b in chargeback.buckets} == {"2026-10": Decimal(16), "2026-11": Decimal(16)}
    assert chargeback.total_invoice == Decimal(32)  # the same physical block counts once per period
def test_union_is_per_period_and_tier(tmp_path):
    root = make_fixture(tmp_path, {
        "teams": {"ds-a": "team-a"},
        "pricing": {"default": {"min_fee": 0, "steps": [{"per_mb": 2}]},
                    "cold": {"min_fee": 0, "steps": [{"per_mb": "0.5"}]}},
        "backups": [{"backup_id": "bk-a1", "dataset_id": "ds-a", "size": 16 * MB}],
        "blocks": [{"block_id": "blk-hot", "size": 8 * MB, "primary_team": "team-a"},
                   {"block_id": "blk-cold", "size": 8 * MB, "primary_team": "team-a", "tier": "cold"}],
        "refs": {"bk-a1": [("blk-hot", 8 * MB), ("blk-cold", 8 * MB)]},
    })
    chargeback = run_pipeline(root).chargeback
    assert {b.tier: b.invoice for b in chargeback.buckets} == {"hot": Decimal(16), "cold": Decimal(4)}
    assert chargeback.total_invoice == Decimal(20)
def test_rates_and_refs_change_invoice_and_witnesses_not_recovery(tmp_path):
    base = run_pipeline(counterexample(tmp_path / "base"))
    pricier = run_pipeline(counterexample(
        tmp_path / "pricier",
        pricing={"default": {"min_fee": 0, "steps": [{"up_to_mb": 10, "per_mb": 3}, {"per_mb": 1}]}},
    ))
    assert pricier.chargeback.total_invoice == Decimal(35)
    assert [c.to_dict() for c in pricier.artifacts] == [c.to_dict() for c in base.artifacts]
    bigger = run_pipeline(counterexample(
        tmp_path / "bigger",
        backups=[{"backup_id": "bk-a1", "dataset_id": "ds-a", "size": 14 * MB},
                 {"backup_id": "bk-b1", "dataset_id": "ds-b", "size": 10 * MB}],
        blocks=[{"block_id": "blk-01-shared", "size": 8 * MB, "primary_team": "team-a"},
                {"block_id": "blk-02-a", "size": 6 * MB, "primary_team": "team-a"},
                {"block_id": "blk-03-b", "size": 2 * MB, "primary_team": "team-b"}],
        refs={"bk-a1": [("blk-01-shared", 8 * MB), ("blk-02-a", 6 * MB)],
              "bk-b1": [("blk-01-shared", 8 * MB), ("blk-03-b", 2 * MB)]},
    ))
    assert bigger.chargeback.total_invoice == Decimal(26)
    assert amounts(bigger.chargeback.contracts[0]) != amounts(base.chargeback.contracts[0])
def test_billing_errors_are_isolated_from_recovery_conclusions(tmp_path):
    good = run_pipeline(counterexample(tmp_path / "good"))
    bad_root = counterexample(tmp_path / "bad")
    (bad_root / "storage" / "objects" / "blk-02-a.bin").write_bytes(b"corrupted")
    bad = run_pipeline(bad_root)
    assert bad.chargeback.status == "unproven"
    assert [f.to_dict() for f in bad.findings] == [f.to_dict() for f in good.findings]
    assert [c.to_dict() for c in bad.artifacts] == [c.to_dict() for c in good.artifacts]
    assert [c.to_dict() for c in bad.chains] == [c.to_dict() for c in good.chains]
    assert [r.to_dict() for r in bad.rpo] == [r.to_dict() for r in good.rpo]
    assert bad.status == good.status
def test_invalid_pricing_config_unproves_bill(tmp_path):
    root = counterexample(tmp_path, pricing={"default": {"min_fee": -1, "steps": [{"per_mb": 1}]}})
    bundle = run_pipeline(root)
    assert bundle.chargeback.status == "unproven"
    assert any(f.rule_id == "BILL-007" for f in bundle.chargeback.findings)
    assert not any(f.rule_id.startswith("BILL-") for f in bundle.findings)
def test_unsafe_inventory_path_is_isolated(tmp_path):
    root = counterexample(tmp_path, chargeback={"inventory_path": "../escape.json"})
    bundle = run_pipeline(root)
    assert bundle.chargeback.status == "unproven"
    assert any(f.rule_id == "BILL-007" for f in bundle.chargeback.findings)
    assert not any(f.rule_id.startswith("BILL-") for f in bundle.findings)
def test_report_renders_chargeback_section(tmp_path):
    report = build_report(run_pipeline(counterexample(tmp_path)))
    section = report["chargeback"]
    assert section["status"] == "settled"
    assert section["physical"]["total_invoice"] == "25"
    assert section["physical"]["buckets"][0]["union_bytes"] == 15 * MB
    assert section["config"]["pricing"]["default"]["steps"][0]["per_mb"] == "2"
    markdown = render_markdown(report)
    assert "## Storage Chargeback" in markdown and "15.5" in markdown
    assert "Storage chargeback" in render_html(report)
def test_legacy_fixture_stays_logical_only(fixtures_root, bundle, report):
    chargeback = bundle.chargeback
    assert chargeback.status == "not_configured"
    assert chargeback.buckets is None and chargeback.total_invoice is None and chargeback.contracts == ()
    assert chargeback.logical_bytes == sum(item.artifact_size_bytes for item in bundle.backups)
    assert not any(f.rule_id.startswith("BILL-") for f in bundle.findings)
    assert report["chargeback"]["status"] == "not_configured"
    assert "Storage Chargeback" not in render_markdown(report)
