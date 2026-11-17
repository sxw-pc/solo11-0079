"""Recovery-generation lineage shared by validation and drill assessment.

A recovery generation starts at a successful ``restore_base``. A later
successful ``restore_base`` opens a newer generation and invalidates evidence
bound to an older one, regardless of attempt numbers. ``apply_incremental`` and
downstream verification bind to a generation through ``recovery_generation`` and
to its final restored data through ``data_digest``.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import Finding
from .records import DrillEvent

RECOVERY_STEPS = frozenset({"restore_base", "apply_incremental"})


@dataclass(frozen=True)
class GenerationView:
    explicit: bool
    generations: tuple[str, ...]
    current: str | None
    final_digest: str | None
    gen_digests: dict[str, str | None]


def uses_generations(events: list[DrillEvent]) -> bool:
    """Old drill logs carry neither new field and keep legacy semantics."""
    return any(event.recovery_generation is not None or event.data_digest is not None for event in events)


def recovery_retried(events: list[DrillEvent]) -> bool:
    counts: dict[str, int] = {}
    for event in events:
        counts[event.step] = counts.get(event.step, 0) + 1
    return any(step in RECOVERY_STEPS for step, count in counts.items() if count > 1)


def _ordered(events: list[DrillEvent]) -> list[DrillEvent]:
    return sorted(events, key=lambda item: (item.started_at, item.line_no))


def analyze_generation(events: list[DrillEvent]) -> GenerationView:
    """Derive generation order, the current generation and its final digest."""
    explicit = uses_generations(events)
    generations: list[str] = []
    gen_digests: dict[str, str | None] = {}
    for event in _ordered(events):
        if event.step != "restore_base" or event.status != "success":
            continue
        gen = event.recovery_generation if explicit else None
        if gen is None:
            continue
        if gen not in generations:
            generations.append(gen)
            gen_digests[gen] = event.data_digest
        elif gen_digests[gen] is None:
            gen_digests[gen] = event.data_digest
    if explicit:
        for event in _ordered(events):
            if (event.step == "apply_incremental" and event.status == "success"
                    and event.recovery_generation in gen_digests and event.data_digest is not None):
                gen_digests[event.recovery_generation] = event.data_digest
    current = generations[-1] if generations else None
    final_digest = gen_digests.get(current) if current is not None else None
    return GenerationView(explicit, tuple(generations), current, final_digest, gen_digests)


def validate_generation_markers(
    events: list[DrillEvent], path: str, file_hash: str
) -> list[Finding]:
    """Cross-row lineage checks: a base opens a generation; increments bind it."""
    out: list[Finding] = []
    grouped: dict[str, list[DrillEvent]] = {}
    for event in events:
        grouped.setdefault(event.drill_id, []).append(event)
    for drill_id in sorted(grouped):
        rows = sorted(grouped[drill_id], key=lambda item: (item.started_at, item.line_no))
        declared: set[str] = set()
        current = None
        for event in rows:
            if event.step == "restore_base" and event.status == "success" and event.recovery_generation:
                if event.recovery_generation in declared:
                    out.append(_gen_finding(event, path, file_hash,
                                            "recovery_generation is reused by another restore_base."))
                declared.add(event.recovery_generation)
                current = event.recovery_generation
        opened = {
            event.recovery_generation
            for event in rows
            if event.step == "restore_base" and event.recovery_generation
        }
        for event in rows:
            if event.step == "restore_base":
                continue
            if event.recovery_generation is not None and event.recovery_generation not in opened:
                out.append(_gen_finding(
                    event, path, file_hash,
                    "recovery_generation does not reference a restore_base attempt."))
            if event.step == "apply_incremental" and event.status == "success":
                if event.recovery_generation is None:
                    if declared:
                        out.append(_gen_finding(
                            event, path, file_hash,
                            "apply_incremental must bind to the current recovery generation."))
                elif event.recovery_generation != current:
                    out.append(_gen_finding(
                        event, path, file_hash,
                        "apply_incremental references a superseded recovery generation."))
    return out


def _gen_finding(event: DrillEvent, path: str, file_hash: str, message: str) -> Finding:
    return Finding("IN-016", "error", "drill_event", event.drill_id, message, path, event.line_no,
                   {"step": event.step, "attempt": event.attempt,
                    "recovery_generation": event.recovery_generation}, file_hash)
