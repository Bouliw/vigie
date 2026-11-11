from pathlib import Path

import pytest
from evtx import PyEvtxParser

from vigie.parsers import winevtx, winxml

FIXTURES = Path(__file__).parent.parent / "fixtures" / "evtx"


def xml_records(path):
    """The records of an EVTX file as Windows renders them in XML (without the declaration)."""
    return [record["data"].split("?>", 1)[1] for record in PyEvtxParser(str(path)).records()]


def normalized(fields):
    # XML turns CR LF into LF, and Windows writes booleans as true/false where the
    # JSON decoder of the evtx library gives Python's True/False.
    def one(value):
        value = value.replace("\r\n", "\n")
        return value.lower() if value in ("True", "False") else value

    return {
        key: tuple(map(one, value)) if isinstance(value, tuple) else one(value)
        for key, value in fields.items()
    }


@pytest.mark.parametrize("path", sorted(FIXTURES.glob("*.evtx")), ids=lambda path: path.name)
def test_same_events_as_the_evtx_parser(path):
    expected = winevtx.parse(path).events
    records = xml_records(path)
    assert len(records) == len(expected)
    for event, record in zip(expected, records, strict=True):
        (element,) = winxml.iter_events(record)
        live = winxml.build_event(element, path.name)
        assert (live.timestamp, live.source, live.event_id, live.host, live.origin) == (
            event.timestamp,
            event.source,
            event.event_id,
            event.host,
            event.origin,
        )
        assert normalized(live.fields) == normalized(event.fields)


def test_wevtutil_document_with_several_events():
    records = xml_records(FIXTURES / "DE_1102_security_log_cleared.evtx")[:3]
    document = "<Events>" + "".join(records) + "</Events>"
    elements = list(winxml.iter_events(document))
    assert [winxml.record_id(element) for element in elements] == [452811, 452812, 452813]
    assert list(winxml.iter_events("  \r\n")) == []


def test_user_data_fields():
    (record, *_) = xml_records(FIXTURES / "DE_1102_security_log_cleared.evtx")
    (element,) = winxml.iter_events(record)
    event = winxml.build_event(element, "Security")
    assert event.source == "security"
    assert event.event_id == 1102
    assert event.origin == "Security#452811"
    assert event.get("SubjectUserName") == "user01"


def test_unnamed_data_items():
    document = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
        "<Provider Name='Service Control Manager'/><EventID Qualifiers='16384'>7036</EventID>"
        "<TimeCreated SystemTime='2026-11-11T08:00:00.000000Z'/><EventRecordID>9</EventRecordID>"
        "<Channel>System</Channel><Computer>PC01</Computer></System>"
        "<EventData><Data>Windows Update</Data><Data>running</Data><Binary>7700</Binary>"
        "</EventData></Event>"
    )
    (element,) = winxml.iter_events(document)
    event = winxml.build_event(element, "System")
    assert event.get("Data") == ("Windows Update", "running")
    assert event.get("Binary") == "7700"
    assert event.get("EventID") == "7036"


@pytest.mark.parametrize(
    ("system", "message"),
    [
        ("", "no System element"),
        ("<System><EventID>x</EventID></System>", "invalid EventID"),
        ("<System><EventID>4625</EventID></System>", "no TimeCreated"),
    ],
)
def test_malformed_events(system, message):
    (element,) = winxml.iter_events(f"<Event>{system}</Event>")
    with pytest.raises(ValueError, match=message):
        winxml.build_event(element, "Security")
