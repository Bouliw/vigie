"""Parser for Windows events rendered as XML, as ``wevtutil qe /f:xml`` prints them.

This is how ``vigie watch --windows`` reads the live event log. An event gets
the same fields as when its ``.evtx`` file is analyzed (see :mod:`winevtx`):
``EventID``, ``Channel``, ``Provider_Name``, ``Computer``, then the named
``Data`` items of ``EventData``, or the elements inside ``UserData``.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from collections.abc import Iterator
from typing import Any

from vigie.models import Event
from vigie.parsers.windows import channel_to_source, field_value
from vigie.timeutils import parse_iso8601


def _local(tag: str) -> str:
    """An element name without its namespace: ``{http://...}EventID`` -> ``EventID``."""
    return tag.rsplit("}", 1)[-1]


def _child(element: ET.Element, name: str) -> ET.Element | None:
    return next((child for child in element if _local(child.tag) == name), None)


def _text(element: ET.Element | None) -> str:
    return "" if element is None else (element.text or "")


def iter_events(document: str) -> Iterator[ET.Element]:
    """The ``<Event>`` elements of a ``wevtutil qe /f:xml /e:Events`` document."""
    if not document.strip():
        return
    root = ET.fromstring(document)
    if _local(root.tag) == "Event":
        yield root
        return
    for child in root:
        if _local(child.tag) == "Event":
            yield child


def record_id(event: ET.Element) -> int:
    """The EventRecordID of an event (0 if it has none)."""
    system = _child(event, "System")
    text = _text(_child(system, "EventRecordID")) if system is not None else ""
    return int(text) if text.strip().isdigit() else 0


def build_event(event: ET.Element, origin_name: str) -> Event:
    """Turn one ``<Event>`` element into an :class:`Event` (``ValueError`` if malformed)."""
    system = _child(event, "System")
    if system is None:
        raise ValueError("no System element")
    event_id_text = _text(_child(system, "EventID")).strip()
    if not event_id_text.isdigit():
        raise ValueError(f"invalid EventID {event_id_text!r}")
    event_id = int(event_id_text)
    channel = _text(_child(system, "Channel"))
    computer = _text(_child(system, "Computer"))
    provider = _child(system, "Provider")
    created = _child(system, "TimeCreated")
    system_time = created.get("SystemTime") if created is not None else None
    if not system_time:
        raise ValueError("no TimeCreated")

    fields: dict[str, Any] = {
        "EventID": str(event_id),
        "Channel": channel,
        "Provider_Name": provider.get("Name", "") if provider is not None else "",
        "Computer": computer,
    }
    fields.update(_event_data(event))
    return Event(
        timestamp=parse_iso8601(system_time),
        source=channel_to_source(channel),
        event_id=event_id,
        host=computer or None,
        fields=fields,
        raw=ET.tostring(event, encoding="unicode"),
        origin=f"{origin_name}#{record_id(event)}",
    )


def _event_data(event: ET.Element) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    event_data = _child(event, "EventData")
    if event_data is not None:
        unnamed: list[str] = []
        for data in event_data:
            name = data.get("Name")
            if name:
                fields[name] = _text(data)
            elif _local(data.tag) == "Data":
                unnamed.append(_text(data))
            else:  # <Binary> and the like, named after their element
                fields[_local(data.tag)] = _text(data)
        if unnamed:
            fields["Data"] = field_value(unnamed if len(unnamed) > 1 else unnamed[0])
    user_data = _child(event, "UserData")
    if user_data is not None:
        for wrapper in user_data:
            for item in wrapper:
                fields[_local(item.tag)] = _text(item)
    return fields
