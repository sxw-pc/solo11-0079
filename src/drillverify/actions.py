"""Attribution and remediation action types."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .rules import SEVERITY_RANK


@dataclass(frozen=True)
class AttributionRecord:
    category: str
    rule_id: str
    severity: str
    object_type: str
    object_id: str
    root_cause: str
    material: bool
    probe: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "object_type": self.object_type,
            "object_id": self.object_id,
            "root_cause": self.root_cause,
            "material": self.material,
            "probe": self.probe,
        }


@dataclass(frozen=True)
class PlanAction:
    action_id: str
    priority: str
    category: str
    owner_team: str
    dataset_id: str
    object_type: str
    object_id: str
    rule_id: str
    rule_ids: tuple[str, ...]
    title: str
    rationale: str
    instruction: str
    due_at: str
    probes: tuple[dict[str, Any], ...]

    def sort_key(self) -> tuple[Any, ...]:
        return (
            SEVERITY_RANK.get(self.priority, 99),
            self.due_at,
            self.dataset_id,
            self.action_id,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "priority": self.priority,
            "category": self.category,
            "owner_team": self.owner_team,
            "dataset_id": self.dataset_id,
            "object_type": self.object_type,
            "object_id": self.object_id,
            "rule_id": self.rule_id,
            "rule_ids": list(self.rule_ids),
            "title": self.title,
            "rationale": self.rationale,
            "instruction": self.instruction,
            "due_at": self.due_at,
            "probes": sorted(
                self.probes,
                key=lambda item: (item.get("file", ""), item.get("line", 0)),
            ),
        }
