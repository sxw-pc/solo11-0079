"""Shared helpers for drill assessment and the same-generation evidence gate."""

from __future__ import annotations

from typing import Any

from .models import Finding

STRICT = "strict_replay"
REUSE = "evidence_reuse"
EVIDENCE_POLICIES = frozenset({STRICT, REUSE})


def drill_finding(
    rule: str, severity: str, drill_id: str, message: str,
    path: str, line: int, file_hash: str, **evidence: Any,
) -> Finding:
    return Finding(rule, severity, "drill", drill_id, message, path, line, evidence, file_hash)
