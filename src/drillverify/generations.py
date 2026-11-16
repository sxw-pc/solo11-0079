"""Recovery-generation binding: which step evidence belongs to the usable restore."""

from __future__ import annotations

from dataclasses import dataclass

from .records import DrillEvent
from .results import EvidenceDecision

RESTORE_STEPS = ("restore_base", "apply_incremental")


@dataclass(frozen=True)
class GenerationState:
    """Same-generation verdict for one drill's restore and verification evidence."""

    current_gen: str | None
    final_digest: str | None
    chain_unbound: bool
    unbound_steps: tuple[str, ...]
    decisions: tuple[EvidenceDecision, ...]


def _order(event: DrillEvent) -> tuple:
    return (event.finished_at, event.line_no)


def _label(gen: str | None) -> str:
    return repr(gen) if gen is not None else "<implicit>"


def _invalid_reason(
    event: DrillEvent,
    gen: str | None,
    chain_unbound: bool,
    final_digest: str | None,
    legacy_implicit: bool,
) -> str:
    if legacy_implicit:
        return "superseded by a higher attempt in the same generation"
    if gen is None:
        return "restore was retried and the event declares no recovery generation"
    if chain_unbound:
        return "apply_incremental is not bound to the current recovery generation"
    if event.recovery_gen != gen:
        return f"recovery generation {_label(event.recovery_gen)} is superseded by {_label(gen)}"
    if final_digest is not None and event.verified_digest != final_digest:
        return "verified digest differs from the current generation final digest"
    return "superseded by a higher attempt in the same generation"


def analyse_generations(
    drill_id: str,
    events: list[DrillEvent],
    required_steps: tuple[str, ...],
    valid_evidence: set[str],
    reuse_allowed: bool,
) -> GenerationState:
    """Bind restore and verification evidence to the latest usable generation.

    A recovery generation opens at each successful restore_base; the latest one
    is current and invalidates earlier generations regardless of attempt
    numbers. apply_incremental, when present, must reference the current
    generation, and its final data digest binds downstream verification.
    """
    restore_at = max(
        (index for index, step in enumerate(required_steps) if step in RESTORE_STEPS),
        default=None,
    )
    downstream = required_steps[restore_at + 1:] if restore_at is not None else ()
    bases = [event for event in events if event.step == "restore_base"]
    applies = [event for event in events if event.step == "apply_incremental"]
    good_bases = sorted((event for event in bases if event.status == "success"), key=_order)
    current = good_bases[-1] if good_bases else None
    gen = current.recovery_gen if current else None
    legacy_implicit = (
        current is not None
        and gen is None
        and len(bases) == 1
        and len(applies) <= 1
        and all(event.status == "success" for event in applies)
    )
    chain_unbound = False
    final_digest = None
    if current is not None and not legacy_implicit:
        if gen is None:
            chain_unbound = bool(applies)
        elif applies:
            in_gen = sorted(
                (e for e in applies if e.recovery_gen == gen and e.status == "success"),
                key=_order,
            )
            chain_unbound = not in_gen
            final_digest = in_gen[-1].verified_digest if in_gen else None
        else:
            final_digest = current.verified_digest

    def binds(event: DrillEvent) -> bool:
        if legacy_implicit:
            return True
        if gen is None or chain_unbound or event.recovery_gen != gen:
            return False
        return final_digest is None or event.verified_digest == final_digest

    decisions: list[EvidenceDecision] = []

    def decide(event: DrillEvent, decision: str, reason: str) -> None:
        decisions.append(
            EvidenceDecision(
                drill_id, event.step, event.attempt, event.line_no,
                decision, reason, event.recovery_gen,
            )
        )

    for event in good_bases:
        if event is current:
            decide(event, "adopted", f"opens the current recovery generation {_label(gen)}")
        else:
            decide(event, "invalidated", f"superseded by a later restore_base (generation {_label(gen)})")
    for event in sorted((e for e in applies if e.status == "success"), key=_order):
        if legacy_implicit or (gen is not None and event.recovery_gen == gen and not chain_unbound):
            decide(event, "adopted", f"belongs to the current recovery generation {_label(gen)}")
        else:
            decide(event, "invalidated", "not bound to the current recovery generation")
    unbound: list[str] = []
    for step in downstream:
        step_events = [event for event in events if event.step == step]
        if not step_events:
            continue
        good = sorted(
            (e for e in step_events if e.status == "success"),
            key=lambda e: (e.attempt, e.line_no),
        )
        bound = [event for event in good if binds(event)]
        adopted = bound[-1] if bound else None
        decision = "adopted"
        if (
            adopted is None and reuse_allowed and gen is not None
            and not chain_unbound and final_digest is not None
        ):
            pool = [
                event
                for event in good
                if event.verified_digest is not None
                and event.verified_digest == final_digest
                and event.evidence_ref in valid_evidence
            ]
            if pool:
                adopted, decision = pool[-1], "reused"
        for event in good:
            if event is adopted:
                if decision == "reused":
                    reason = "verified digest equals the current generation final digest; reused"
                elif legacy_implicit:
                    reason = "single unambiguous restore generation"
                else:
                    reason = f"bound to the current recovery generation {_label(gen)}"
                decide(event, decision, reason)
            else:
                decide(event, "invalidated", _invalid_reason(event, gen, chain_unbound, final_digest, legacy_implicit))
        if adopted is None:
            effective = max(step_events, key=lambda e: (e.attempt, e.line_no))
            if effective.status == "success":
                unbound.append(step)
    ordered = tuple(sorted(decisions, key=lambda item: (item.line_no, item.step, item.attempt)))
    return GenerationState(gen, final_digest, chain_unbound, tuple(unbound), ordered)
