"""Maintenance-window parsing and discrete 30-minute slot generation."""

from __future__ import annotations

import math
import re
from datetime import datetime, time, timedelta, timezone

_WINDOW_RE = re.compile(
    r"^(?P<day>mon|tue|wed|thu|fri|sat|sun):"
    r"(?P<start>[01]\d|2[0-3]):(?P<start_min>[0-5]\d)-"
    r"(?P<end>[01]\d|2[0-3]):(?P<end_min>[0-5]\d)Z$"
)
_DAY_INDEX = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}


def parse_window(label: str) -> tuple[int, int, int] | None:
    """Return (weekday, start minute-of-day, end minute-of-day) or None."""
    match = _WINDOW_RE.fullmatch(label.strip())
    if match is None:
        return None
    start = int(match.group("start")) * 60 + int(match.group("start_min"))
    end = int(match.group("end")) * 60 + int(match.group("end_min"))
    if end <= start:
        return None
    return _DAY_INDEX[match.group("day").lower()], start, end


def _ceil_slot(minutes: float, slot_minutes: int) -> int:
    return int(math.ceil(minutes / slot_minutes))


def allowed_start_slots(
    label: str,
    as_of: datetime,
    horizon_end: datetime,
    duration_minutes: int,
    slot_minutes: int,
) -> tuple[int, ...]:
    """Enumerate every discrete slot index where an action fits in its window."""
    parsed = parse_window(label)
    if parsed is None or duration_minutes <= 0 or slot_minutes <= 0:
        return ()
    weekday, start_minute, end_minute = parsed
    duration_slots = _ceil_slot(duration_minutes, slot_minutes)
    horizon_slots = int((horizon_end - as_of).total_seconds() // 60 // slot_minutes)
    starts: set[int] = set()
    day = as_of.date()
    # Scan a full week beyond the horizon so a late window still clips cleanly.
    for offset in range((horizon_end.date() - day).days + 8):
        current = day + timedelta(days=offset)
        if current.weekday() != weekday:
            continue
        window_start = datetime.combine(current, time(0, 0), tzinfo=timezone.utc) + timedelta(
            minutes=start_minute
        )
        window_end = datetime.combine(current, time(0, 0), tzinfo=timezone.utc) + timedelta(
            minutes=end_minute
        )
        if window_end <= as_of:
            continue
        if window_start >= horizon_end:
            break
        first = _ceil_slot(max((window_start - as_of).total_seconds() / 60, 0), slot_minutes)
        last = int((window_end - as_of).total_seconds() // 60 // slot_minutes)
        last = min(last, horizon_slots)
        for start in range(first, last - duration_slots + 1):
            if start >= 0 and start + duration_slots <= min(last, horizon_slots):
                starts.add(start)
    return tuple(sorted(starts))
