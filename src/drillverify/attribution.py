"""Failure attribution: stable categories, severity and evidence probes."""

from __future__ import annotations

from collections import Counter

from .actions import AttributionRecord
from .models import Finding
from .rules import SEVERITY_RANK, category_for

_MATERIAL = {"critical", "high", "error", "medium"}


def attribute(findings: tuple[Finding, ...]) -> tuple[tuple[AttributionRecord, ...], dict]:
    """Map every finding to one auditable root-cause category."""
    records = [
        AttributionRecord(
            category=category_for(item.rule_id),
            rule_id=item.rule_id,
            severity=item.severity,
            object_type=item.object_type,
            object_id=item.object_id,
            root_cause=item.message,
            material=item.severity in _MATERIAL,
            probe=item.probe(),
        )
        for item in findings
    ]
    records.sort(
        key=lambda item: (
            SEVERITY_RANK.get(item.severity, 99),
            item.category,
            item.object_type,
            item.object_id,
            item.rule_id,
        )
    )
    category_counts = Counter(item.category for item in records)
    material_counts = Counter(item.category for item in records if item.material)
    severity_counts = Counter(item.severity for item in records)
    summary = {
        "material_count": sum(1 for item in records if item.material),
        "record_count": len(records),
        "by_category": {
            category: {
                "total": category_counts[category],
                "material": material_counts[category],
            }
            for category in sorted(category_counts)
        },
        "by_severity": {severity: severity_counts[severity] for severity in sorted(severity_counts)},
    }
    return tuple(records), summary
