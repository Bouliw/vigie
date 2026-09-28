import json
import os
import zipfile
from collections import Counter
from datetime import datetime, timedelta

import pytest

from vigie.parsers import winjson
from vigie.timeutils import UTC

FIXTURES = os.path.join(os.path.dirname(__file__), "..", "fixtures", "winjson")
BITSADMIN = os.path.join(FIXTURES, "cmd_bitsadmin_download_psh_script_excerpt.json")
NAME = "cmd_bitsadmin_download_psh_script_excerpt.json"


@pytest.fixture(scope="module")
def parsed():
    return winjson.parse(BITSADMIN)


def test_all_events_are_parsed(parsed):
    assert len(parsed.events) == 10
    assert Counter(e.source for e in parsed.events) == {"security": 3, "sysmon": 7}
    assert {e.host for e in parsed.events} == {"WORKSTATION5"}


def test_clock_is_corrected_from_sysmon_utctime(parsed):
    assert parsed.warnings == [
        f"{NAME}: timestamps shifted by +04:00 to match Sysmon UtcTime (local time labeled as UTC)"
    ]
    bitsadmin = parsed.events[4]
    assert bitsadmin.origin == f"{NAME}:5"
    # @timestamp says 02:36:43.547Z, Sysmon UtcTime says 06:36:43.542.
    assert bitsadmin.timestamp == datetime(2020, 10, 23, 6, 36, 43, 547000, tzinfo=UTC)
    # The shift applies to Security events of the same file too.
    assert parsed.events[0].timestamp == datetime(2020, 10, 23, 6, 36, 43, 542000, tzinfo=UTC)


def test_sysmon_process_creation_fields(parsed):
    event = parsed.events[4]
    assert event.event_id == 1
    assert event.get("EventID") == "1"
    assert event.get("Image") == "C:\\Windows\\System32\\bitsadmin.exe"
    assert "/transfer" in event.get("CommandLine")
    assert event.get("Provider_Name") == "Microsoft-Windows-Sysmon"
    assert event.get("Computer") == "WORKSTATION5"


def test_security_event_fields(parsed):
    event = parsed.events[0]
    assert event.event_id == 4688
    assert event.get("NewProcessName") == "C:\\Windows\\System32\\bitsadmin.exe"
    assert event.get("Provider_Name") == "Microsoft-Windows-Security-Auditing"


def test_message_is_raw_text_not_a_field(parsed):
    event = parsed.events[4]
    assert event.raw.startswith("Process Create:")
    assert event.get("Message") is None
    assert event.get("@timestamp") is None


def test_zip_archive(tmp_path):
    archive = tmp_path / "dataset.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.write(BITSADMIN, "dataset.json")
        zf.writestr("readme.txt", "ignored")
    result = winjson.parse(archive)
    assert len(result.events) == 10
    assert result.events[0].origin == "dataset.zip/dataset.json:1"


def test_bad_zip(tmp_path):
    archive = tmp_path / "broken.zip"
    archive.write_text("not a zip")
    result = winjson.parse(archive)
    assert result.events == []
    assert result.warnings[0].startswith("broken.zip: cannot open archive")


def write_lines(path, rows):
    path.write_text("\n".join(r if isinstance(r, str) else json.dumps(r) for r in rows) + "\n")


def security_row(**extra):
    row = {"Channel": "Security", "EventID": 4625, "@timestamp": "2024-01-01T00:00:00Z"}
    row.update(extra)
    return row


def test_bad_lines_are_warnings(tmp_path):
    log = tmp_path / "events.json"
    write_lines(
        log,
        [
            security_row(TargetUserName="admin"),
            "{not json",
            {"message": "no channel"},
            security_row(EventID="abc"),
            {"Channel": "Security", "EventID": 4625},
            security_row(**{"@timestamp": "yesterday"}),
            "",
        ],
    )
    result = winjson.parse(log)
    assert len(result.events) == 1
    assert result.events[0].get("TargetUserName") == "admin"
    assert [w.split(": ", 1)[0] for w in result.warnings] == [
        "events.json:2",
        "events.json:3",
        "events.json:4",
        "events.json:5",
        "events.json:6",
    ]
    assert "invalid JSON" in result.warnings[0]
    assert "no timestamp field" in result.warnings[3]


def test_raw_falls_back_to_json_and_host_can_be_missing(tmp_path):
    log = tmp_path / "events.json"
    write_lines(log, [security_row()])
    (event,) = winjson.parse(log).events
    assert json.loads(event.raw)["EventID"] == 4625
    assert event.host is None


def test_naive_timestamp_is_utc_and_no_shift_without_sysmon(tmp_path):
    log = tmp_path / "events.json"
    write_lines(log, [security_row(**{"@timestamp": None, "EventTime": "2024-01-01 10:00:00"})])
    result = winjson.parse(log)
    assert result.warnings == []
    assert result.events[0].timestamp == datetime(2024, 1, 1, 10, 0, tzinfo=UTC)


def sysmon_row(timestamp, utc_time):
    return {
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "EventID": 1,
        "@timestamp": timestamp,
        "UtcTime": utc_time,
    }


def test_negative_offset_and_majority_vote(tmp_path):
    log = tmp_path / "events.json"
    write_lines(
        log,
        [
            sysmon_row("2024-01-01T12:00:00Z", "2024-01-01 06:30:01.000"),
            sysmon_row("2024-01-01T12:01:00Z", "2024-01-01 06:31:00.500"),
            # A delayed network event (a few seconds off) still rounds to -5:30...
            sysmon_row("2024-01-01T12:02:10Z", "2024-01-01 06:32:04.000"),
            # ...and one inconsistent record is outvoted.
            sysmon_row("2024-01-01T12:03:00Z", "2024-01-01 12:03:00.000"),
            sysmon_row("2024-01-01T12:04:00Z", "not a date"),
        ],
    )
    result = winjson.parse(log)
    assert "shifted by -05:30" in result.warnings[0]
    assert result.events[0].timestamp == datetime(2024, 1, 1, 6, 30, tzinfo=UTC)


def test_format_offset():
    assert winjson._format_offset(timedelta(hours=4)) == "+04:00"
    assert winjson._format_offset(timedelta(hours=-9, minutes=-30)) == "-09:30"
