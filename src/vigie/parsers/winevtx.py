"""Parser for Windows event log files (``.evtx``): Security, System, Sysmon, PowerShell...

The binary format is decoded by the ``evtx`` library (Rust, MIT license), which
yields each record as JSON. This module flattens that JSON into an
:class:`~vigie.models.Event`:

* ``System`` gives the timestamp, EventID, channel, provider and computer;
* ``EventData`` (most events) or ``UserData`` (e.g. 1102, log cleared) give the
  event-specific fields, named as in the Windows schema (``TargetUserName``,
  ``Image``, ``CommandLine``...). These are the names Sigma rules use.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from evtx import PyEvtxParser

from vigie.models import Event
from vigie.parsers.base import ParseResult
from vigie.parsers.windows import channel_to_source, field_value
from vigie.timeutils import parse_iso8601

# Stop reading a file after this many consecutive unreadable records: past
# that point the file is corrupted beyond recovery, and continuing could loop.
MAX_CONSECUTIVE_ERRORS = 100


def parse(path: str | Path) -> ParseResult:
    """Parse one ``.evtx`` file."""
    path = Path(path)
    result = ParseResult()
    try:
        records = PyEvtxParser(str(path)).records_json()
    except (OSError, RuntimeError) as exc:
        result.warnings.append(f"{path.name}: cannot open EVTX file ({exc})")
        return result

    consecutive_errors = 0
    while True:
        try:
            record = next(records)
        except StopIteration:
            break
        except Exception as exc:  # the Rust decoder raises generic errors
            consecutive_errors += 1
            result.warnings.append(f"{path.name}: unreadable record ({exc})")
            if consecutive_errors >= MAX_CONSECUTIVE_ERRORS:
                result.warnings.append(f"{path.name}: too many unreadable records, file skipped")
                break
            continue
        consecutive_errors = 0
        fallback_id = record.get("event_record_id", "?")
        try:
            result.events.append(_build_event(json.loads(record["data"]), path.name, fallback_id))
        except (KeyError, TypeError, ValueError) as exc:
            result.warnings.append(f"{path.name}#{fallback_id}: malformed record ({exc!r})")
    return result


def _build_event(record: dict[str, Any], file_name: str, fallback_id: object) -> Event:
    event = record["Event"]
    system = event["System"]
    # EventRecordID is the number Event Viewer shows; the decoder's own counter
    # is only a fallback for records that lack it.
    record_id = system.get("EventRecordID", fallback_id)

    event_id = int(str(field_value(system["EventID"])))
    channel = str(field_value(system.get("Channel")))
    computer = str(field_value(system.get("Computer")))
    provider = system.get("Provider", {}).get("#attributes", {}).get("Name", "")
    timestamp = parse_iso8601(system["TimeCreated"]["#attributes"]["SystemTime"])

    fields: dict[str, Any] = {
        "EventID": str(event_id),
        "Channel": channel,
        "Provider_Name": provider,
        "Computer": computer,
    }
    fields.update(_event_data(event))

    return Event(
        timestamp=timestamp,
        source=channel_to_source(channel),
        event_id=event_id,
        host=computer or None,
        fields=fields,
        raw=json.dumps(event, ensure_ascii=False, separators=(",", ":")),
        origin=f"{file_name}#{record_id}",
    )


def _event_data(event: dict[str, Any]) -> dict[str, Any]:
    """Collect the event-specific fields from ``EventData`` or ``UserData``."""
    fields: dict[str, Any] = {}
    event_data = event.get("EventData")
    if isinstance(event_data, dict):
        for name, value in event_data.items():
            if name != "#attributes":
                fields[name] = field_value(value)

    # UserData wraps its fields in one provider-specific element,
    # e.g. <UserData><LogFileCleared><SubjectUserName>...
    user_data = event.get("UserData")
    if isinstance(user_data, dict):
        for name, wrapper in user_data.items():
            if name == "#attributes" or not isinstance(wrapper, dict):
                continue
            for field_name, value in wrapper.items():
                if field_name != "#attributes":
                    fields[field_name] = field_value(value)
    return fields
