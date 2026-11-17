"""Same-generation evidence gate for drill verification steps.

Downstream steps must evidence the current recovery generation; evidence bound
to an older generation is invalidated even with a higher attempt number. After
a recovery retry without current-generation evidence, the configured policy
decides whether identical-digest prior evidence may be reused. A data digest
that contradicts the current generation is always a hard failure, independent
of whether a retry occurred.
"""

from __future__ import annotations

from .drill_common import REUSE, drill_finding as _finding
from .generations import RECOVERY_STEPS, recovery_retried
from .models import Finding
from .records import DrillEvent
from .results import StepEvidence


def _record(drill_id: str, event: DrillEvent, decision: str, reason: str) -> StepEvidence:
    return StepEvidence(
        drill_id=drill_id, step=event.step, attempt=event.attempt, line=event.line_no,
        evidence_ref=event.evidence_ref, decision=decision, reason=reason,
        recovery_generation=event.recovery_generation, data_digest=event.data_digest,
    )


def generation_gate(
    drill_id: str,
    drill_events: list[DrillEvent],
    effective: dict[str, DrillEvent],
    view,
    required: set[str],
    policy: str,
    valid_evidence: set[str],
    drill_path: str,
    drill_hash: str,
) -> tuple[bool, bool, list[Finding], list[StepEvidence]]:
    """Return (hard_ok, gate_ok, findings, ledger).

    ``hard_ok`` is False for digest contradictions; ``gate_ok`` is False when
    retried recovery leaves downstream evidence unproven for this generation.
    """
    downstream = sorted(required - RECOVERY_STEPS - {"precheck"})
    findings: list[Finding] = []
    ledger: list[StepEvidence] = []
    hard_blocks: list[str] = []
    blocked: list[str] = []
    strict_pending: list[str] = []
    reused: list[str] = []
    retried = recovery_retried(drill_events)
    for step in downstream:
        candidate = effective.get(step)
        if candidate is None:
            continue
        if not view.explicit:
            ledger.append(_record(drill_id, candidate, "adopted",
                                  "legacy log without recovery-generation markers"))
            continue
        if candidate.recovery_generation == view.current:
            if view.final_digest is not None and candidate.data_digest not in (None, view.final_digest):
                hard_blocks.append(step)
                ledger.append(_record(drill_id, candidate, "invalidated",
                                      "bound to current generation but data digest differs"))
            else:
                ledger.append(_record(drill_id, candidate, "adopted",
                                      "bound to the current recovery generation"))
            continue
        stale = bool(_stale_event(drill_events, step, view))
        stale_reason = ("bound to a recovery generation superseded by a later restore_base"
                        if stale else _block_reason(candidate, view))
        reusable = (view.final_digest is not None
                    and candidate.data_digest == view.final_digest
                    and candidate.evidence_ref in valid_evidence)
        if policy == REUSE and reusable:
            reused.append(step)
            ledger.append(_record(drill_id, candidate, "reused",
                                  "identical full data digest and valid evidence file"))
        elif reusable:
            strict_pending.append(step)
            ledger.append(_record(drill_id, candidate, "invalidated",
                                  "strict replay requires re-verification after a new generation"))
        else:
            blocked.append(step)
            ledger.append(_record(drill_id, candidate, "invalidated", stale_reason))

    line = min(event.line_no for event in drill_events)
    if hard_blocks:
        findings.append(_finding("EVID-013", "high", drill_id,
            "Verification evidence contradicts the current recovery data digest.",
            drill_path, line, drill_hash, blocked_steps=sorted(set(hard_blocks)),
            current_generation=view.current, final_data_digest=view.final_digest))
    if retried and view.explicit:
        if blocked:
            findings.append(_finding("EVID-010", "high", drill_id,
                "Recovery was retried and downstream evidence is not from the current generation.",
                drill_path, line, drill_hash, blocked_steps=sorted(set(blocked)),
                current_generation=view.current, final_data_digest=view.final_digest))
        if strict_pending:
            findings.append(_finding("EVID-011", "medium", drill_id,
                "Strict replay policy: re-run downstream verification for the new recovery "
                "generation; identical-digest evidence cannot be reused.",
                drill_path, line, drill_hash, pending_steps=sorted(set(strict_pending)),
                current_generation=view.current))
        if reused:
            findings.append(_finding("EVID-012", "info", drill_id,
                "Evidence-reuse policy accepted prior verification bound to an identical digest.",
                drill_path, line, drill_hash, reused_steps=sorted(set(reused)),
                data_digest=view.final_digest))
    pending = blocked or strict_pending
    gate_ok = not (retried and view.explicit and pending)
    return not hard_blocks, gate_ok, findings, ledger


def _stale_event(events: list[DrillEvent], step: str, view) -> list[DrillEvent]:
    return [event for event in events
            if event.step == step and event.recovery_generation is not None
            and event.recovery_generation != view.current]


def _block_reason(candidate: DrillEvent, view) -> str:
    if view.final_digest is None:
        return "current recovery generation declares no final data digest"
    if candidate.data_digest is None:
        return "verification evidence carries no data digest"
    if candidate.data_digest != view.final_digest:
        return "verification data digest differs from the current generation digest"
    return "evidence file is missing or invalid"
