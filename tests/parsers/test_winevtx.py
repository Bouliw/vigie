import json
import os
from collections import Counter
from datetime import datetime

import pytest

from vigie.parsers import winevtx
from vigie.parsers.windows import channel_to_source, field_value
from vigie.timeutils import UTC

FIXTURES = os.path.join(os.path.dirname(__file__), "..", "fixtures", "evtx")
SYSMON_LSASS = os.path.join(FIXTURES, "sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx")
LOG_CLEARED = os.path.join(FIXTURES, "DE_1102_security_log_cleared.evtx")
ACCOUNT_CREATED = os.path.join(FIXTURES, "DE_Fake_ComputerAccount_4720.evtx")
SERVICE_INSTALLED = os.path.join(FIXTURES, "LM_Remote_Service02_7045.evtx")


def test_sysmon_event():
    result = winevtx.parse(SYSMON_LSASS)
    assert result.warnings == []
    (event,) = result.events
    assert event.source == "sysmon"
    assert event.event_id == 10
    assert event.host == "PC04.example.corp"
    assert event.timestamp == datetime(2019, 3, 17, 19, 37, 11, 661930, tzinfo=UTC)
    assert event.origin == "sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx#4807"
    assert event.get("EventID") == "10"
    assert event.get("Channel") == "Microsoft-Windows-Sysmon/Operational"
    assert event.get("Provider_Name") == "Microsoft-Windows-Sysmon"
    assert event.get("TargetImage") == "C:\\Windows\\system32\\lsass.exe"
    assert event.get("SourceImage").endswith("\\mimikatz.exe")
    assert event.get("GrantedAccess") == "0x1010"
    # Numbers are normalized to strings.
    assert event.get("SourceProcessId") == "3588"


def test_security_log_with_user_data():
    result = winevtx.parse(LOG_CLEARED)
    assert result.warnings == []
    assert Counter(e.event_id for e in result.events) == {4663: 110, 1102: 1, 5156: 1}
    assert {e.source for e in result.events} == {"security"}

    (cleared,) = [e for e in result.events if e.event_id == 1102]
    # 1102 stores its fields under UserData/LogFileCleared.
    assert cleared.get("SubjectUserName") == "user01"
    assert cleared.get("SubjectDomainName") == "EXAMPLE"
    assert cleared.timestamp == datetime(2019, 3, 19, 23, 35, 7, 524202, tzinfo=UTC)


def test_security_event_data():
    result = winevtx.parse(ACCOUNT_CREATED)
    assert [e.event_id for e in result.events] == [4720, 4720]
    event = result.events[0]
    assert event.get("TargetUserName") == "$"
    assert event.get("SamAccountName") == "$"
    assert event.get("SubjectUserSid") == "S-1-5-18"


def test_system_event_with_qualified_event_id():
    # <EventID Qualifiers="16384">7045</EventID> is decoded as a dict.
    result = winevtx.parse(SERVICE_INSTALLED)
    assert [e.event_id for e in result.events] == [7045, 7045, 7045]
    event = result.events[0]
    assert event.source == "system"
    assert event.get("EventID") == "7045"
    assert event.get("ServiceName") == "spoolfool"
    assert event.get("ImagePath") == "cmd.exe"


def test_raw_is_compact_json_of_the_record():
    (event,) = winevtx.parse(SYSMON_LSASS).events
    raw = json.loads(event.raw)
    assert raw["System"]["EventRecordID"] == 4807
    assert "\n" not in event.raw


def test_not_an_evtx_file(tmp_path):
    junk = tmp_path / "junk.evtx"
    junk.write_text("not an evtx file")
    result = winevtx.parse(junk)
    assert result.events == []
    assert result.warnings[0].startswith("junk.evtx: cannot open EVTX file")


class ResumableRecords:
    """An iterator that raises on some records but keeps going, like the Rust decoder."""

    def __init__(self, items):
        self._items = iter(items)

    def __iter__(self):
        return self

    def __next__(self):
        item = next(self._items)
        if isinstance(item, Exception):
            raise item
        return item


def fake_parser(monkeypatch, items):
    class Parser:
        def __init__(self, _path):
            pass

        def records_json(self):
            return ResumableRecords(items)

    monkeypatch.setattr(winevtx, "PyEvtxParser", Parser)


def valid_record(record_id=1):
    data = {
        "Event": {
            "System": {
                "EventID": 4625,
                "Channel": "Security",
                "Computer": "HOST",
                "TimeCreated": {"#attributes": {"SystemTime": "2024-01-01T00:00:00Z"}},
            },
            "EventData": {"TargetUserName": "admin"},
        }
    }
    return {"event_record_id": record_id, "data": json.dumps(data)}


def test_unreadable_record_is_skipped(monkeypatch):
    fake_parser(monkeypatch, [valid_record(1), RuntimeError("bad chunk"), valid_record(3)])
    result = winevtx.parse("fake.evtx")
    assert len(result.events) == 2
    assert result.warnings == ["fake.evtx: unreadable record (bad chunk)"]


def test_origin_falls_back_to_decoder_record_number(monkeypatch):
    fake_parser(monkeypatch, [valid_record(7)])
    (event,) = winevtx.parse("fake.evtx").events
    assert event.origin == "fake.evtx#7"


def test_user_data_ignores_non_element_children(monkeypatch):
    record = valid_record()
    data = json.loads(record["data"])
    del data["Event"]["EventData"]
    data["Event"]["UserData"] = {"#attributes": {"x": 1}, "Text": "plain", "Wrapper": {"A": "1"}}
    record["data"] = json.dumps(data)
    fake_parser(monkeypatch, [record])
    (event,) = winevtx.parse("fake.evtx").events
    assert event.get("A") == "1"
    assert event.get("Text") is None


def test_malformed_record_is_skipped(monkeypatch):
    broken = {"event_record_id": 2, "data": json.dumps({"Event": {"System": {}}})}
    fake_parser(monkeypatch, [broken, valid_record(3)])
    result = winevtx.parse("fake.evtx")
    assert [e.origin for e in result.events] == ["fake.evtx#3"]
    assert result.warnings[0].startswith("fake.evtx#2: malformed record")


def test_gives_up_after_too_many_consecutive_errors(monkeypatch):
    errors = [RuntimeError("bad")] * (winevtx.MAX_CONSECUTIVE_ERRORS + 5)
    fake_parser(monkeypatch, [*errors, valid_record()])
    result = winevtx.parse("fake.evtx")
    assert result.events == []
    assert result.warnings[-1] == "fake.evtx: too many unreadable records, file skipped"
    assert len(result.warnings) == winevtx.MAX_CONSECUTIVE_ERRORS + 1


@pytest.mark.parametrize(
    ("channel", "source"),
    [
        ("Security", "security"),
        ("System", "system"),
        ("Microsoft-Windows-Sysmon/Operational", "sysmon"),
        ("Microsoft-Windows-PowerShell/Operational", "powershell"),
        ("Windows PowerShell", "powershell-classic"),
        ("Some-Custom/Channel", "some-custom/channel"),
    ],
)
def test_channel_to_source(channel, source):
    assert channel_to_source(channel) == source


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (4625, "4625"),
        (None, ""),
        ({"#attributes": {"Qualifiers": 16384}, "#text": 7045}, "7045"),
        (["a", 1], ("a", "1")),
        ({"b": 2, "a": 1}, '{"a": 1, "b": 2}'),
    ],
)
def test_field_value(raw, expected):
    assert field_value(raw) == expected


def test_event_data_overrides_system_fields_of_the_same_name(monkeypatch):
    # Event 104 names the cleared log in UserData/LogFileCleared/Channel; Sigma
    # rules read that value as "Channel", while the source stays the event's own.
    record = valid_record()
    data = json.loads(record["data"])
    data["Event"]["System"].update({"EventID": 104, "Channel": "System"})
    del data["Event"]["EventData"]
    data["Event"]["UserData"] = {"LogFileCleared": {"Channel": "Security"}}
    record["data"] = json.dumps(data)
    fake_parser(monkeypatch, [record])
    (event,) = winevtx.parse("fake.evtx").events
    assert event.source == "system"
    assert event.get("Channel") == "Security"
