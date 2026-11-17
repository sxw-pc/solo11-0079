from __future__ import annotations
import shutil
from pathlib import Path
import pytest
from drillverify.pipeline import run_pipeline
from drillverify.reporting import build_report
ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"
@pytest.fixture(scope="session")
def fixtures_root() -> Path:
    return FIXTURES
@pytest.fixture(scope="session")
def bundle(fixtures_root: Path):
    return run_pipeline(fixtures_root)
@pytest.fixture(scope="session")
def report(bundle):
    return build_report(bundle)
@pytest.fixture
def fixture_copy(tmp_path: Path) -> Path:
    target = tmp_path / "fixtures"
    shutil.copytree(FIXTURES, target)
    return target
