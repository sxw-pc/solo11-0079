"""UTC timestamp parsing and deterministic formatting helpers."""
from __future__ import annotations
import re
from datetime import datetime, timedelta, timezone
_ISO_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$"
)
class TimestampError(ValueError):
    """Raised when an input timestamp is not valid ISO 8601."""
def parse_utc(value: object, *, require_z: bool = False) -> datetime:
    """Parse an ISO 8601 timestamp and return an aware UTC datetime."""
    if not isinstance(value, str) or not _ISO_RE.fullmatch(value.strip()):
        raise TimestampError("expected ISO 8601 timestamp with Z or offset")
    text = value.strip()
    if require_z and not text.endswith("Z"):
        raise TimestampError("expected UTC timestamp ending in Z")
    candidate = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:  # pragma: no cover - regex already constrains shape
        raise TimestampError("invalid ISO 8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise TimestampError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)
def format_utc(value: datetime) -> str:
    """Format a datetime as second-precision UTC with a trailing Z."""
    if value.tzinfo is None:
        raise ValueError("naive datetimes are not allowed")
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )
def format_date(value: datetime) -> str:
    return format_utc(value)[:10]
def minutes_between(start: datetime, end: datetime) -> int:
    """Return whole elapsed minutes, rounded down deterministically."""
    seconds = (end - start).total_seconds()
    return int(seconds // 60)
def add_days(value: datetime, days: int) -> datetime:
    return value + timedelta(days=days)
