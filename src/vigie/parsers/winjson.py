"""Parser for Windows events exported as JSON lines, the format of OTRF Security-Datasets.

Each line is one event, flattened: ``{"Channel": "Security", "EventID": 4688,
"Hostname": ..., "@timestamp": ..., "NewProcessName": ...}``. OTRF ships these
files inside ``.zip`` archives, which are read directly.

Clock correction: in several OTRF datasets ``@timestamp`` holds the lab's
*local* time wrongly labeled as UTC (``Z``). Sysmon events carry their own
``UtcTime`` field, which is reliable. When a file contains Sysmon events, the
parser measures the gap between both clocks, rounds it to the nearest 15
minutes (timezone offsets are multiples of 15 minutes) and shifts every event
in the file by that amount, so the timeline stays consistent with other logs.
"""

from __future__ import annotations

import io
import json
import zipfile
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from vigie.models import Event
from vigie.parsers.base import ParseResult
from vigie.parsers.windows import channel_to_source, field_value
from vigie.timeutils import UTC, parse_iso8601

TIMESTAMP_KEYS = ("@timestamp", "TimeCreated", "EventTime")
OFFSET_STEP = timedelta(minutes=15)


@dataclass
class _Row:
    origin: str
    data: dict[str, Any]
    channel: str
    event_id: int
    timestamp: datetime


def parse(path: str | Path) -> ParseResult:
    """Parse a ``.json`` / ``.jsonl`` file, or every ``.json`` member of a ``.zip``."""
    path = Path(path)
    result = ParseResult()
    rows = list(_read_rows(path, result))

    offset = _clock_offset(rows)
    if offset:
        result.warnings.append(
            f"{path.name}: timestamps shifted by {_format_offset(offset)} "
            "to match Sysmon UtcTime (local time labeled as UTC)"
        )
    for row in rows:
        result.events.append(_build_event(row, offset))
    return result


def _read_rows(path: Path, result: ParseResult) -> Iterator[_Row]:
    if path.suffix == ".zip":
        try:
            archive = zipfile.ZipFile(path)
        except zipfile.BadZipFile as exc:
            result.warnings.append(f"{path.name}: cannot open archive ({exc})")
            return
        with archive:
            for member in archive.namelist():
                if member.endswith((".json", ".jsonl")):
                    with archive.open(member) as raw:
                        text = io.TextIOWrapper(raw, encoding="utf-8", errors="replace")
                        yield from _parse_lines(f"{path.name}/{member}", text, result)
    else:
        with path.open(encoding="utf-8", errors="replace") as text:
            yield from _parse_lines(path.name, text, result)


def _parse_lines(name: str, lines: Iterable[str], result: ParseResult) -> Iterator[_Row]:
    for lineno, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        origin = f"{name}:{lineno}"
        try:
            data = json.loads(line)
        except json.JSONDecodeError as exc:
            result.warnings.append(f"{origin}: invalid JSON ({exc.msg})")
            continue
        if not isinstance(data, dict) or "Channel" not in data or "EventID" not in data:
            result.warnings.append(f"{origin}: not a Windows event (no Channel or EventID)")
            continue
        try:
            event_id = int(str(field_value(data["EventID"])))
            timestamp = _timestamp(data)
        except ValueError as exc:
            result.warnings.append(f"{origin}: {exc}")
            continue
        yield _Row(origin, data, str(data["Channel"]), event_id, timestamp)


def _timestamp(data: dict[str, Any]) -> datetime:
    for key in TIMESTAMP_KEYS:
        if data.get(key):
            # Exports without an offset are UTC by convention.
            return parse_iso8601(str(data[key]), default_tz=UTC)
    raise ValueError("no timestamp field")


def _clock_offset(rows: list[_Row]) -> timedelta:
    """Most common gap between Sysmon's UtcTime and the export timestamp, in 15-minute steps."""
    votes: Counter[timedelta] = Counter()
    for row in rows:
        utc_time = row.data.get("UtcTime")
        if channel_to_source(row.channel) != "sysmon" or not utc_time:
            continue
        try:
            true_time = parse_iso8601(str(utc_time), default_tz=UTC)
        except ValueError:
            continue
        steps = round((true_time - row.timestamp) / OFFSET_STEP)
        votes[steps * OFFSET_STEP] += 1
    if not votes:
        return timedelta(0)
    return votes.most_common(1)[0][0]


def _format_offset(offset: timedelta) -> str:
    sign = "-" if offset < timedelta(0) else "+"
    minutes = abs(int(offset.total_seconds())) // 60
    return f"{sign}{minutes // 60:02d}:{minutes % 60:02d}"


def _build_event(row: _Row, offset: timedelta) -> Event:
    data = row.data
    fields: dict[str, Any] = {
        key: field_value(value)
        for key, value in data.items()
        if not key.startswith("@") and key != "Message"
    }
    # Same names as the EVTX parser, so one Sigma rule works on both formats.
    fields["EventID"] = str(row.event_id)
    fields["Channel"] = row.channel
    fields["Provider_Name"] = str(field_value(data.get("SourceName")))
    fields["Computer"] = str(field_value(data.get("Hostname")))

    message = data.get("Message")
    return Event(
        timestamp=row.timestamp + offset,
        source=channel_to_source(row.channel),
        event_id=row.event_id,
        host=fields["Computer"] or None,
        fields=fields,
        raw=message if isinstance(message, str) and message else json.dumps(data),
        origin=row.origin,
    )
