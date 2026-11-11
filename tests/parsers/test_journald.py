import json
from datetime import datetime

from vigie.parsers import authlog, journald
from vigie.timeutils import UTC

NOW = datetime(2024, 3, 11, tzinfo=UTC)
ENTRY = {
    "__REALTIME_TIMESTAMP": "1710061200123456",  # 2024-03-10 09:00:00.123456 UTC
    "_HOSTNAME": "web01",
    "SYSLOG_IDENTIFIER": "sshd-session",
    "_PID": "812",
    "_COMM": "sshd-session",
    "MESSAGE": "Failed password for invalid user admin from 203.0.113.9 port 51234 ssh2",
}


def parse(entry, warnings=None):
    return journald.parse_line(
        json.dumps(entry), lineno=7, now=NOW, warnings=[] if warnings is None else warnings
    )


def test_entry_reads_like_the_auth_log_line():
    (event,) = parse(ENTRY)
    line = (
        "2024-03-10T09:00:00.123456+00:00 web01 sshd-session[812]: "
        "Failed password for invalid user admin from 203.0.113.9 port 51234 ssh2"
    )
    (expected,) = authlog.parse_line(line, name="journald", lineno=7, now=NOW).events
    assert event == expected
    assert event.origin == "journald:7"
    assert event.timestamp == datetime(2024, 3, 10, 9, 0, 0, 123456, tzinfo=UTC)
    assert event.get("action") == "ssh_failed_password"
    assert event.get("src_ip") == "203.0.113.9"
    assert event.get("user") == "admin"


def test_syslog_pid_comes_first_and_missing_fields_have_defaults():
    entry = {**ENTRY, "SYSLOG_PID": "900"}
    del entry["_HOSTNAME"]
    (event,) = parse(entry)
    assert event.get("pid") == "900"
    assert event.host == "localhost"


def test_sudo_entry():
    entry = {
        **ENTRY,
        "SYSLOG_IDENTIFIER": "sudo",
        "MESSAGE": "   alice : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/alice ; "
        "USER=root ; COMMAND=/usr/bin/cat /etc/shadow",
    }
    (event,) = parse(entry)
    assert event.get("action") == "sudo_auth_failure"
    assert event.get("command") == "/usr/bin/cat /etc/shadow"


def test_binary_and_repeated_fields():
    message = "Failed password for invalid user ren\xe9 from 203.0.113.9 port 4000 ssh2"
    entry = {
        **ENTRY,
        "SYSLOG_IDENTIFIER": ["sshd", "sshd"],
        "MESSAGE": list(message.encode("latin-1")),  # not UTF-8: journalctl gives the bytes
    }
    (event,) = parse(entry)
    assert event.get("program") == "sshd"
    assert event.get("user") == "ren\ufffd"
    assert event.get("src_ip") == "203.0.113.9"


def test_a_message_on_several_lines_stays_one_entry():
    entry = {
        **ENTRY,
        "MESSAGE": "Connection closed by 198.51.100.1 port 22\n"
        "2024-03-10T09:00:01+00:00 web01 sshd[1]: Accepted password for root from "
        "198.51.100.66 port 4000 ssh2",
    }
    events = parse(entry)
    assert len(events) == 1
    assert events[0].get("action") != "ssh_accepted"


def test_entries_without_message_or_time_are_skipped():
    warnings = []
    assert parse({**ENTRY, "MESSAGE": None}, warnings) == []
    assert parse({k: v for k, v in ENTRY.items() if k != "__REALTIME_TIMESTAMP"}, warnings) == []
    assert warnings == []


def test_lines_that_are_not_entries_are_reported():
    warnings = []
    assert journald.parse_line("-- No entries --", lineno=1, now=NOW, warnings=warnings) == []
    assert journald.parse_line("[1, 2]", lineno=2, now=NOW, warnings=warnings) == []
    assert journald.parse_line("", lineno=3, now=NOW, warnings=warnings) == []
    assert warnings == [
        "journald:1: not a JSON journal entry",
        "journald:2: not a JSON journal entry",
    ]


def test_identifiers_are_those_of_the_auth_log_parser():
    assert set(journald.IDENTIFIERS) == authlog.AUTH_PROGRAMS
