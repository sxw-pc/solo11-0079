"""Path confinement and hashing helpers.
Every fixture path is relative to a single fixture root. Absolute paths, drive
letters, traversal components and resolved escapes are rejected before I/O.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path, PurePosixPath
class UnsafePath(ValueError):
    """Raised when a declared fixture path escapes the fixture root."""
def normalize_relative(value: object, *, field: str = "path") -> str:
    """Validate and normalize a POSIX-style relative path."""
    if not isinstance(value, str) or not value.strip():
        raise UnsafePath(f"{field} must be a non-empty relative path")
    raw = value.strip()
    if "\\" in raw:
        raise UnsafePath(f"{field} must use forward slashes")
    pure = PurePosixPath(raw)
    if pure.is_absolute() or raw.startswith("~"):
        raise UnsafePath(f"{field} must not be absolute")
    if any(part in {"", ".", ".."} for part in pure.parts):
        raise UnsafePath(f"{field} must not contain traversal components")
    if ":" in raw.split("/", 1)[0]:
        raise UnsafePath(f"{field} must not contain a drive or scheme")
    return pure.as_posix()
def resolve_under(root: Path, value: object, *, field: str = "path") -> Path:
    """Return an absolute path proven to stay under ``root``."""
    rel = normalize_relative(value, field=field)
    root_resolved = root.resolve()
    candidate = (root_resolved / rel).resolve()
    try:
        candidate.relative_to(root_resolved)
    except ValueError as exc:
        raise UnsafePath(f"{field} escapes the fixture root") from exc
    return candidate
def safe_relative(root: Path, candidate: Path) -> str:
    """Represent a path relative to root using POSIX separators."""
    return candidate.resolve().relative_to(root.resolve()).as_posix()
def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()
def sha256_file(path: Path, chunk_size: int = 65536) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()
def stable_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
