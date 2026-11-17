from __future__ import annotations
import socket
from pathlib import Path
from drillverify.pipeline import run_pipeline
from drillverify.reporting import build_report
def test_pipeline_runs_with_network_primitives_disabled(monkeypatch, fixtures_root: Path):
    attempts = []
    def deny(*args, **kwargs):
        attempts.append((args, kwargs))
        raise AssertionError("network access attempted")
    monkeypatch.setattr(socket.socket, "connect", deny)
    monkeypatch.setattr(socket, "create_connection", deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)
    bundle = run_pipeline(fixtures_root)
    report = build_report(bundle)
    assert report["status"] == "fail"
    assert attempts == []
def test_source_has_no_network_client_dependencies():
    forbidden = (
        "import requests", "import httpx", "import aiohttp",
        "import urllib.request", "import http.client", "from urllib import request",
    )
    root = Path(__file__).resolve().parents[1] / "src" / "drillverify"
    for path in root.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert not any(token in text for token in forbidden), path.name
def test_templates_and_styles_have_no_remote_assets():
    root = Path(__file__).resolve().parents[1] / "src" / "drillverify"
    for path in list(root.rglob("*.html")) + list(root.rglob("*.css")):
        text = path.read_text(encoding="utf-8").lower()
        assert "http://" not in text and "https://" not in text
        assert "//cdn" not in text and "@import" not in text
def test_allowed_hosts_are_loopback_only():
    from drillverify.web import ALLOWED_HOSTS
    assert ALLOWED_HOSTS == {"127.0.0.1", "localhost", "::1"}
