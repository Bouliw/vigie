"""Timestamp helpers.

Every timestamp inside Vigie is a timezone-aware ``datetime`` in UTC. Parsers
convert at the boundary so that sorting, correlation windows and the report
timeline never mix local and UTC times.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone, tzinfo

UTC = timezone.utc

# Python 3.10's fromisoformat() rejects a trailing "Z" and fractions longer than
# six digits, both of which are common in logs (EVTX SystemTime uses seven).
_FRACTION = re.compile(r"\.(\d+)")


def ensure_utc(value: datetime) -> datetime:
    """Return ``value`` converted to UTC. Naive datetimes are rejected.

    A naive datetime is ambiguous (local time of which host?), so the caller
    must decide which timezone applies and attach it explicitly.
    """
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(f"naive datetime is ambiguous, attach a timezone first: {value!r}")
    return value.astimezone(UTC)


def parse_iso8601(text: str, default_tz: tzinfo | None = None) -> datetime:
    """Parse an ISO 8601 timestamp and return it in UTC.

    Accepts a trailing ``Z``, a space instead of ``T`` and fractional seconds
    of any length (truncated to microseconds). A timestamp without an offset
    is interpreted in ``default_tz``; if none is given it is rejected.
    """
    normalized = text.strip()
    if normalized.endswith(("Z", "z")):
        normalized = normalized[:-1] + "+00:00"
    normalized = _FRACTION.sub(lambda m: "." + m.group(1)[:6].ljust(6, "0"), normalized, count=1)
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"invalid ISO 8601 timestamp: {text!r}") from exc
    if parsed.tzinfo is None:
        if default_tz is None:
            raise ValueError(f"timestamp has no timezone and no default was given: {text!r}")
        parsed = parsed.replace(tzinfo=default_tz)
    return ensure_utc(parsed)
