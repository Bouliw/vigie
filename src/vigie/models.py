"""Core data model shared by parsers, the detection engine and the report."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType
from typing import Any

from vigie.timeutils import ensure_utc


@dataclass(frozen=True, slots=True)
class Event:
    """One normalized log event, whatever file format it came from.

    Attributes:
        timestamp: When the event happened, always timezone-aware UTC.
        source: Log channel the event belongs to, lowercase ("security",
            "sysmon", "system", "auth"...). Sigma rules are routed on it.
        event_id: Numeric event identifier (Windows EventID); ``None`` for
            formats that have none, such as auth.log.
        host: Machine that produced the event, when known.
        fields: Named values extracted by the parser. Sigma selections match
            against these keys. Stored as a read-only mapping.
        raw: The original record as text. Sigma keyword searches run on it
            and the report shows it as evidence.
        origin: Where the event was read from ("file.evtx#42",
            "auth.log:17"), so an analyst can go back to the source.
    """

    timestamp: datetime
    source: str
    event_id: int | None = None
    host: str | None = None
    fields: Mapping[str, Any] = field(default_factory=dict)
    raw: str = ""
    origin: str = ""

    def __post_init__(self) -> None:
        if not self.source:
            raise ValueError("event source must not be empty")
        # frozen=True blocks normal assignment, so normalize via object.__setattr__.
        object.__setattr__(self, "timestamp", ensure_utc(self.timestamp))
        object.__setattr__(self, "source", self.source.lower())
        object.__setattr__(self, "fields", MappingProxyType(dict(self.fields)))

    def get(self, name: str, default: Any = None) -> Any:
        """Return the value of field ``name``, or ``default`` if absent."""
        return self.fields.get(name, default)


# Sigma severity levels, from least to most severe.
LEVELS = ("informational", "low", "medium", "high", "critical")


@dataclass(frozen=True, slots=True)
class RuleMeta:
    """Descriptive part of a rule: everything the report shows about it.

    ``kind`` is ``"detection"`` for a rule matching single events and
    ``"correlation"`` for a rule matching patterns across several events.
    """

    id: str
    title: str
    level: str
    kind: str = "detection"
    name: str | None = None
    description: str = ""
    status: str = ""
    author: str = ""
    date: str = ""
    references: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    falsepositives: tuple[str, ...] = ()
    license: str = ""  # e.g. "DRL-1.1" for rules adapted from SigmaHQ
    path: str = ""

    def __post_init__(self) -> None:
        if self.level not in LEVELS:
            raise ValueError(f"unknown level {self.level!r}, expected one of {', '.join(LEVELS)}")

    @property
    def severity(self) -> int:
        """Rank of the level: 0 (informational) to 4 (critical), for sorting."""
        return LEVELS.index(self.level)


@dataclass(frozen=True, slots=True)
class Alert:
    """A rule that fired, with the events that made it fire.

    A detection alert holds one event. A correlation alert holds every event
    that contributed (e.g. all failed logins of a brute force) and the
    ``group`` values they share (e.g. ``{"src_ip": "203.0.113.45"}``).
    """

    rule: RuleMeta
    events: tuple[Event, ...]
    group: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.events:
            raise ValueError("an alert needs at least one event")
        ordered = tuple(sorted(self.events, key=lambda event: event.timestamp))
        object.__setattr__(self, "events", ordered)
        object.__setattr__(self, "group", MappingProxyType(dict(self.group)))

    @property
    def timestamp(self) -> datetime:
        """Time of the first contributing event."""
        return self.events[0].timestamp

    @property
    def last_seen(self) -> datetime:
        """Time of the last contributing event."""
        return self.events[-1].timestamp
