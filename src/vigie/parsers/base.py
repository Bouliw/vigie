"""Types shared by all parsers."""

from __future__ import annotations

from dataclasses import dataclass, field

from vigie.models import Event


@dataclass
class ParseResult:
    """Output of one parser run on one file.

    A parser never raises on a bad record: it skips it and explains why in
    ``warnings``, so one corrupted line cannot hide the rest of a file from
    the analyst. The warnings end up in the report's ingestion statistics.
    """

    events: list[Event] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
