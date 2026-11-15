from __future__ import annotations

from pathlib import Path

import pytest

from drillverify.ledger import record_run
from drillverify.reporting import build_report
from drillverify.web import create_app, validate_bind_host


@pytest.fixture
def app(bundle, tmp_path: Path):
    db = tmp_path / "ledger.sqlite3"
    record_run(db, bundle, build_report(bundle))
    application = create_app(db)
    application.config.update(TESTING=True)
    return application


def test_read_only_views_render(app):
    client = app.test_client()
    index = client.get("/")
    assert index.status_code == 200 and b"Verification runs" in index.data
    run = client.get("/runs/1")
    assert run.status_code == 200 and b"Dataset posture" in run.data
    dataset = client.get("/runs/1/datasets/ds-orders")
    assert dataset.status_code == 200 and b"Backup chain" in dataset.data
    findings = client.get("/runs/1/findings?severity=critical")
    assert findings.status_code == 200 and b"OBJ-POINT-001" in findings.data
    plan = client.get("/runs/1/plan")
    assert plan.status_code == 200 and b"Remediation and re-drill plan" in plan.data
    assert client.get("/healthz").get_json() == {"status": "ok", "read_only": True}


def test_missing_resources_and_writes_are_rejected(app):
    client = app.test_client()
    assert client.get("/runs/999").status_code == 404
    assert client.get("/runs/1/datasets/ds-absent").status_code == 404
    assert client.post("/runs/1").status_code == 405
    assert client.delete("/runs/1/plan").status_code == 405


def test_only_get_routes_are_registered(app):
    for rule in app.url_map.iter_rules():
        assert "POST" not in rule.methods
        assert "PUT" not in rule.methods
        assert "PATCH" not in rule.methods
        assert "DELETE" not in rule.methods


def test_loopback_binding_is_enforced():
    assert validate_bind_host("127.0.0.1") == "127.0.0.1"
    assert validate_bind_host("localhost") == "localhost"
    assert validate_bind_host("::1") == "::1"
    for bad in ("0.0.0.0", "192.0.2.10", "example.test", ""):
        with pytest.raises(ValueError):
            validate_bind_host(bad)
