"""Deterministic remediation and re-drill plan generation."""

from __future__ import annotations

from collections import Counter
from typing import Any

from .actions import PlanAction, action_revision, canonical_probes
from .models import Finding, RecoveryPlan
from .paths import sha256_bytes, stable_json
from .records import BackupRecord, DrillEvent
from .rules import (
    SLA_DAYS,
    category_for,
    remediation_for,
    title_for,
)
from .timeutil import add_days, format_date

_MATERIAL = {"critical", "high", "error", "medium"}


def _dataset_owner(
    finding: Finding,
    owners: dict[str, str],
    backup_owner: dict[str, str],
    drill_owner: dict[str, str],
) -> tuple[str, str]:
    if finding.object_type == "dataset" and finding.object_id in owners:
        return finding.object_id, owners[finding.object_id]
    if finding.object_type == "backup" and finding.object_id in backup_owner:
        dataset_id = backup_owner[finding.object_id]
        return dataset_id, owners.get(dataset_id, "unassigned")
    if finding.object_type == "drill" and finding.object_id in drill_owner:
        dataset_id = drill_owner[finding.object_id]
        return dataset_id, owners.get(dataset_id, "unassigned")
    return "", "unassigned"


def build_plan(
    plan: RecoveryPlan,
    findings: tuple[Finding, ...],
    backups: tuple[BackupRecord, ...],
    events: tuple[DrillEvent, ...],
) -> tuple[tuple[PlanAction, ...], dict[str, Any]]:
    """Group actionable findings into owner-assigned, due-dated actions."""
    owners = {dataset.dataset_id: dataset.owner_team for dataset in plan.datasets}
    backup_owner = {item.backup_id: item.dataset_id for item in backups}
    drill_owner = {item.drill_id: item.dataset_id for item in events}
    groups: dict[tuple[str, str, str, str, str], list[Finding]] = {}
    for finding in findings:
        if finding.severity not in _MATERIAL:
            continue
        dataset_id, owner = _dataset_owner(finding, owners, backup_owner, drill_owner)
        category = category_for(finding.rule_id)
        key = (category, owner, dataset_id, finding.object_type, finding.object_id)
        groups.setdefault(key, []).append(finding)
    actions: list[PlanAction] = []
    for (category, owner, dataset_id, object_type, object_id), members in groups.items():
        members.sort(key=Finding.sort_key)
        lead = members[0]
        severity = lead.severity
        rule_ids = tuple(sorted({member.rule_id for member in members}))
        probes = {tuple(sorted(member.probe().items())): member.probe() for member in members}
        canonical = canonical_probes(tuple(probes.values()))
        canonical_probes_tuple = tuple(canonical)
        source_inputs = tuple(
            sorted({probe["input_sha256"] for probe in canonical if probe["input_sha256"]})
        )
        rationale = " | ".join(sorted({member.message for member in members}))
        due = format_date(add_days(plan.as_of, SLA_DAYS.get(severity, 14)))
        action_seed = stable_json(
            [category, owner, dataset_id, object_type, object_id, list(rule_ids)]
        )
        actions.append(
            PlanAction(
                action_id=sha256_bytes(action_seed.encode("utf-8"))[:12],
                priority=severity,
                category=category,
                owner_team=owner,
                dataset_id=dataset_id,
                object_type=object_type,
                object_id=object_id,
                rule_id=lead.rule_id,
                rule_ids=rule_ids,
                title=f"{title_for(lead.rule_id)}: {object_type} {object_id}",
                rationale=rationale,
                instruction=remediation_for(lead.rule_id),
                due_at=due,
                probes=canonical_probes_tuple,
                revision=action_revision(severity, rule_ids, canonical_probes_tuple, source_inputs),
                source_inputs=source_inputs,
            )
        )
    actions.sort(key=PlanAction.sort_key)
    priority_counts = Counter(action.priority for action in actions)
    category_counts = Counter(action.category for action in actions)
    summary = {
        "action_count": len(actions),
        "by_priority": {key: priority_counts[key] for key in sorted(priority_counts)},
        "by_category": {key: category_counts[key] for key in sorted(category_counts)},
        "next_due_at": min((action.due_at for action in actions), default=None),
    }
    return tuple(actions), summary
