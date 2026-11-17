"""Attribution and remediation action types."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from .paths import sha256_bytes, stable_json
from .rules import SEVERITY_RANK


def canonical_probes(probes: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Stable ordering of evidence probes for digesting and display."""
    return sorted(
        probes,
        key=lambda item: (
            str(item.get("file", "")),
            int(item.get("line", 0) or 0),
            str(item.get("rule_id", "")),
            str(item.get("input_sha256", "")),
        ),
    )


def action_revision(
    priority: str,
    rule_ids: tuple[str, ...] | list[str],
    probes: Iterable[dict[str, Any]],
    source_inputs: Iterable[str],
) -> str:
    """Digest of everything an approver attests to for one action.

    Approval is bound to this digest: a later run that changes the priority,
    rule set, probe locations or probe input hashes produces a new revision, so
    an old approval can never be inherited by the changed action.
    """
    seed = stable_json(
        {
            "priority": priority,
            "rule_ids": sorted(rule_ids),
            "probes": canonical_probes(probes),
            "source_inputs": sorted(source_inputs),
        }
    )
    return sha256_bytes(seed.encode("utf-8"))[:16]


def revision_for(action: "PlanAction") -> str:
    """Use the stored revision, or recompute one for older action payloads."""
    if getattr(action, "revision", ""):
        return str(action.revision)
    return action_revision(
        action.priority,
        tuple(action.rule_ids),
        tuple(action.probes),
        tuple(getattr(action, "source_inputs", ())),
    )


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
    revision: str = ""
    source_inputs: tuple[str, ...] = ()

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
            "revision": self.revision,
            "source_inputs": list(self.source_inputs),
            "probes": sorted(
                self.probes,
                key=lambda item: (item.get("file", ""), item.get("line", 0)),
            ),
        }
