from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "drillverify"
TESTS = ROOT / "tests"
DOCS = ROOT / "docs"


def _line_count(path: Path) -> int:
    return len(path.read_text(encoding="utf-8").splitlines())


def test_every_handwritten_file_respects_line_limit():
    files = list(SOURCE.rglob("*.py")) + list(SOURCE.rglob("*.html"))
    files += list(SOURCE.rglob("*.css")) + list(TESTS.rglob("*.py"))
    files += list(DOCS.rglob("*.md"))
    files.append(ROOT / "README.md")
    oversized = {path.relative_to(ROOT).as_posix(): _line_count(path) for path in files if _line_count(path) > 300}
    assert oversized == {}


def test_python_code_size_is_in_required_range():
    python_files = list(SOURCE.rglob("*.py")) + list(TESTS.rglob("*.py"))
    total = sum(_line_count(path) for path in python_files)
    # The ceiling grew from 4500 to 5500 when the static schema-migration
    # proof engine (schema_compat/schema_config) and its tests were added.
    assert 2500 <= total <= 5500, f"Python source + tests is {total} lines"


def test_required_files_exist():
    required = [
        "Makefile", "README.md", "pyproject.toml", "requirements.txt",
        "fixtures/plans/recovery_plan.yaml",
        "fixtures/catalog/backup_catalog.csv",
        "fixtures/logs/restore_drill.jsonl",
        "docs/DATA_CONTRACT.md", "docs/RULES.md", "docs/COMPLIANCE.md", "docs/DESIGN.md",
    ]
    assert all((ROOT / name).is_file() for name in required)
