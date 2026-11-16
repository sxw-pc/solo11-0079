"""Rule catalogue, categories and deterministic remediation guidance."""

from __future__ import annotations

SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "error": 2,
    "medium": 3,
    "warning": 4,
    "low": 5,
    "info": 6,
}

RULE_TITLES = {
    "CFG-001": "Recovery plan field is invalid",
    "CFG-002": "Duplicate dataset declaration",
    "CFG-003": "Recovery plan has no usable datasets",
    "CFG-004": "Unsafe artifact manifest path",
    "IN-000": "Required input file is missing",
    "IN-001": "Required catalog column missing",
    "IN-002": "Required value missing",
    "IN-003": "Field has an invalid type or range",
    "IN-004": "Timestamp is invalid",
    "IN-005": "Duplicate backup identifier",
    "IN-006": "Unknown dataset identifier",
    "IN-007": "Unknown backup identifier",
    "IN-008": "Invalid enum value",
    "IN-009": "Unsafe fixture path",
    "IN-010": "Invalid evidence reference",
    "IN-011": "Invalid SHA-256 digest",
    "IN-012": "Malformed JSONL record",
    "IN-013": "Invalid drill status",
    "IN-014": "Drill identity conflict",
    "IN-015": "Timestamp order is invalid",
    "IN-016": "Recovery generation identifier is invalid",
    "IN-017": "Verified digest requires a recovery generation",
    "IN-018": "Unknown recovery generation reference",
    "CHAIN-001": "Backup parent is missing",
    "CHAIN-002": "Incremental backup is orphaned",
    "CHAIN-003": "Backup parent cycle detected",
    "CHAIN-004": "Parent backup finishes after child starts",
    "CHAIN-005": "Parent schema version is incompatible",
    "CHAIN-006": "Backup timestamp is in the future",
    "CHAIN-009": "Ancestor backup is not restorable",
    "ART-001": "Artifact manifest is missing",
    "ART-002": "Artifact manifest is malformed",
    "ART-003": "Artifact file is missing",
    "ART-004": "Artifact size differs from catalog",
    "ART-005": "Artifact SHA-256 differs from catalog",
    "ART-006": "Manifest disagrees with catalog",
    "EVID-001": "Evidence file is missing",
    "EVID-002": "Evidence file is invalid",
    "EVID-004": "Required drill step is missing",
    "EVID-005": "Required drill step failed",
    "EVID-006": "Required drill step was skipped",
    "EVID-007": "Drill retried a step",
    "EVID-008": "Drill contains an unexpected step",
    "EVID-009": "Drill references a non-restorable backup",
    "CONS-001": "Restored row count differs from manifest",
    "CONS-002": "Restored checksum differs from manifest",
    "CONS-003": "Required row count is unavailable",
    "CONS-004": "Required checksum is unavailable",
    "CONS-005": "Verification evidence is not bound to the current recovery generation",
    "CONS-006": "Incremental apply is not bound to the current recovery generation",
    "OBJ-POINT-001": "Dataset has no restorable point",
    "OBJ-RPO-001": "Recovery point objective is breached",
    "OBJ-RTO-001": "Recovery time objective is breached",
}

RULE_CATEGORIES = {
    "CFG": "configuration",
    "IN": "input_quality",
    "CHAIN": "chain_integrity",
    "ART": "artifact_integrity",
    "EVID": "evidence_integrity",
    "CONS": "data_consistency",
    "OBJ-POINT": "recoverability",
    "OBJ-RPO": "rpo_gap",
    "OBJ-RTO": "rto_gap",
}

REMEDIATION = {
    "configuration": "Correct the recovery plan and rerun offline validation.",
    "input_quality": "Correct the synthetic source row; never suppress a validation error.",
    "chain_integrity": "Rebuild a complete chain rooted at a full backup, then rerun the drill.",
    "artifact_integrity": "Restore the artifact and manifest, reconcile SHA-256 and size, then rerun.",
    "evidence_integrity": "Capture the required evidence and complete every mandatory drill step.",
    "data_consistency": "Reconcile restored row count and checksum with the artifact manifest.",
    "recoverability": "Create a complete full backup with a valid artifact before the next drill.",
    "rpo_gap": "Add restorable points or revise the backup cadence to meet the RPO.",
    "rto_gap": "Reduce restore duration or file a reviewed recovery-target change.",
    "general": "Investigate the cited evidence and schedule a controlled re-drill.",
}

SLA_DAYS = {"critical": 1, "high": 3, "error": 3, "medium": 7, "warning": 14, "low": 14}


def category_for(rule_id: str) -> str:
    """Resolve a rule ID to one stable failure-attribution category."""
    for prefix, category in RULE_CATEGORIES.items():
        if rule_id.startswith(prefix + "-"):
            return category
    return "general"


def title_for(rule_id: str) -> str:
    return RULE_TITLES.get(rule_id, rule_id)


def remediation_for(rule_id: str) -> str:
    return REMEDIATION.get(category_for(rule_id), REMEDIATION["general"])
