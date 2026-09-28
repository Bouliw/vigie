import gzip
import os
import shutil
from collections import Counter
from datetime import datetime, timedelta, timezone

import pytest

from vigie.parsers import authlog
from vigie.timeutils import UTC

FIXTURES = os.path.join(os.path.dirname(__file__), "..", "fixtures", "authlog")
AUTH_LOG = os.path.join(FIXTURES, "auth.log")
ROLLOVER_LOG = os.path.join(FIXTURES, "auth_rollover.log")
RFC3339_LOG = os.path.join(FIXTURES, "auth_rfc3339.log")


@pytest.fixture(scope="module")
def parsed():
    return authlog.parse(AUTH_LOG, year=2024)


def by_origin(result, lineno):
    (event,) = [e for e in result.events if e.origin == f"auth.log:{lineno}"]
    return event


def test_every_syslog_line_becomes_an_event(parsed):
    assert len(parsed.events) == 29
    assert all(event.source == "auth" for event in parsed.events)
    assert all(event.host == "web01" for event in parsed.events)
    assert all(event.event_id is None for event in parsed.events)


def test_unrecognized_line_is_a_warning_not_a_crash(parsed):
    assert parsed.warnings == ["auth.log:30: unrecognized syslog line"]


def test_classic_timestamp_uses_given_year_and_utc(parsed):
    assert parsed.events[0].timestamp == datetime(2024, 3, 10, 8, 58, 1, tzinfo=UTC)


def test_program_pid_and_message(parsed):
    event = by_origin(parsed, 1)
    assert event.get("program") == "CRON"
    assert event.get("pid") == "1201"
    assert event.get("message").startswith("pam_unix(cron:session)")
    assert event.get("action") is None
    assert event.raw.startswith("Mar 10 08:58:01 web01 CRON[1201]:")


def test_actions_are_recognized(parsed):
    actions = Counter(e.get("action") for e in parsed.events if e.get("action"))
    assert actions == {
        "ssh_failed_password": 13,
        "ssh_accepted": 3,
        "ssh_invalid_user": 1,
        "sudo_command": 1,
        "sudo_auth_failure": 1,
        "su_session": 1,
        "user_created": 1,
    }


def test_failed_password_fields(parsed):
    event = by_origin(parsed, 6)
    assert event.get("action") == "ssh_failed_password"
    assert event.get("user") == "oracle"
    assert event.get("invalid_user") == "true"
    assert event.get("src_ip") == "203.0.113.45"
    assert event.get("src_port") == "40022"
    assert event.get("auth_method") == "password"
    assert by_origin(parsed, 7).get("invalid_user") == "false"


def test_accepted_fields(parsed):
    event = by_origin(parsed, 3)
    assert event.get("action") == "ssh_accepted"
    assert event.get("user") == "deploy"
    assert event.get("auth_method") == "publickey"
    assert event.get("src_ip") == "192.0.2.10"


def test_sudo_fields(parsed):
    command = by_origin(parsed, 20)
    assert command.get("action") == "sudo_command"
    assert command.get("user") == "opsadmin"
    assert command.get("target_user") == "root"
    assert command.get("command") == "/usr/sbin/useradd -m -s /bin/bash svc_update"

    failure = by_origin(parsed, 24)
    assert failure.get("action") == "sudo_auth_failure"
    assert failure.get("user") == "deploy"
    assert failure.get("attempts") == "3"


def test_user_created_and_su(parsed):
    created = by_origin(parsed, 23)
    assert created.get("action") == "user_created"
    assert created.get("user") == "svc_update"
    assert created.get("uid") == "1003"
    assert created.get("shell") == "/bin/bash"

    su = by_origin(parsed, 26)
    assert su.get("action") == "su_session"
    assert su.get("user") == "opsadmin"
    assert su.get("target_user") == "root"


def test_year_rollover():
    result = authlog.parse(ROLLOVER_LOG, year=2023)
    stamps = [event.timestamp for event in result.events]
    assert stamps[0] == datetime(2023, 12, 31, 23, 59, 58, tzinfo=UTC)
    assert stamps[1] == datetime(2024, 1, 1, 0, 0, 3, tzinfo=UTC)
    assert stamps == sorted(stamps)


def test_year_is_inferred_from_file_mtime(tmp_path):
    copy = tmp_path / "auth.log"
    shutil.copy(ROLLOVER_LOG, copy)
    mtime = datetime(2025, 1, 2, tzinfo=UTC).timestamp()
    os.utime(copy, (mtime, mtime))
    result = authlog.parse(copy)
    # The last line lands in the mtime year, the first one before the rollover.
    assert result.events[0].timestamp.year == 2024
    assert result.events[-1].timestamp.year == 2025


def test_classic_timestamps_use_given_timezone():
    utc_plus_1 = timezone(timedelta(hours=1))
    result = authlog.parse(ROLLOVER_LOG, year=2023, tz=utc_plus_1)
    assert result.events[0].timestamp == datetime(2023, 12, 31, 22, 59, 58, tzinfo=UTC)


def test_rfc3339_lines_keep_their_own_offset():
    result = authlog.parse(RFC3339_LOG, year=1999, tz=timezone(timedelta(hours=-5)))
    assert [e.timestamp for e in result.events] == [
        datetime(2024, 6, 1, 12, 0, 0, 123456, tzinfo=UTC),
        datetime(2024, 6, 1, 12, 0, 5, 654321, tzinfo=UTC),
        datetime(2024, 6, 1, 12, 1, 0, tzinfo=UTC),
    ]
    assert result.events[0].get("user") == "postgres"
    assert result.events[2].get("target_user") == "postgres"
    assert result.warnings == []


def test_gzip_rotated_log(tmp_path):
    compressed = tmp_path / "auth.log.2.gz"
    with open(AUTH_LOG, "rb") as src, gzip.open(compressed, "wb") as dst:
        dst.write(src.read())
    result = authlog.parse(compressed, year=2024)
    assert len(result.events) == 29
    assert result.events[0].origin == "auth.log.2.gz:1"


def test_invalid_date_is_a_warning(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("Feb 29 10:00:00 web01 sshd[1]: Accepted publickey for deploy from 192.0.2.1\n")
    result = authlog.parse(log, year=2023)
    assert result.events == []
    assert len(result.warnings) == 1
    assert "invalid date" in result.warnings[0]


def test_invalid_rfc3339_date_is_a_warning(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("2024-02-30T10:00:00Z web01 sshd[1]: Connection closed\n")
    result = authlog.parse(log)
    assert result.events == []
    assert result.warnings[0].startswith("auth.log:1: invalid ISO 8601")


def test_line_without_program_keeps_whole_message(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("Mar 10 09:00:00 web01 -- MARK --\n")
    (event,) = authlog.parse(log, year=2024).events
    assert event.get("program") is None
    assert event.get("message") == "-- MARK --"


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("Mar 10 09:05:40 web01 sshd[1344]: Invalid user oracle from 203.0.113.45", True),
        ("2024-06-01T14:00:00Z db01 sudo:   deploy : TTY=pts/0 ; COMMAND=/bin/ls", True),
        ("Mar 10 09:00:00 web01 kernel: [    0.000000] Linux version 6.1", False),
        ("Mar 10 09:00:00 web01 -- MARK --", False),
        ("not syslog at all", False),
    ],
)
def test_is_auth_line(line, expected):
    assert authlog.is_auth_line(line) is expected


def test_empty_and_blank_file(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("\n\n")
    result = authlog.parse(log, year=2024)
    assert result.events == []
    assert result.warnings == []


def parse_line(tmp_path, message, program="sshd"):
    log = tmp_path / "auth.log"
    log.write_text(f"Mar 10 09:00:00 web01 {program}[1]: {message}\n")
    (event,) = authlog.parse(log, year=2024).events
    return event


class TestSshSourceAttribution:
    """The client chooses the user name: it must never decide the source address."""

    def test_fake_source_in_user_name(self, tmp_path):
        event = parse_line(
            tmp_path,
            "Failed password for invalid user x from 192.0.2.10 port 1 "
            "from 198.51.100.66 port 53000 ssh2",
        )
        assert event.get("src_ip") == "198.51.100.66"
        assert event.get("src_port") == "53000"
        assert event.get("user") == "x from 192.0.2.10 port 1"
        assert event.get("invalid_user") == "true"

    def test_fake_source_with_ssh2_in_user_name(self, tmp_path):
        event = parse_line(
            tmp_path,
            "Failed password for invalid user test from 10.10.1.2 port 55555 ssh2 "
            "from 198.51.100.66 port 58946 ssh2",
        )
        assert event.get("src_ip") == "198.51.100.66"

    def test_user_name_with_spaces(self, tmp_path):
        event = parse_line(
            tmp_path, "Failed password for invalid user  0101 from 203.0.113.7 port 4242 ssh2"
        )
        assert event.get("user") == " 0101"
        assert event.get("src_ip") == "203.0.113.7"

    def test_empty_user_name(self, tmp_path):
        event = parse_line(
            tmp_path, "Failed none for invalid user  from 203.0.113.7 port 4242 ssh2"
        )
        assert event.get("user") == ""
        assert event.get("auth_method") == "none"

    def test_public_key_with_key_information(self, tmp_path):
        event = parse_line(
            tmp_path,
            "Failed publickey for deploy from 192.0.2.60 port 50000 ssh2: RSA SHA256:abc",
        )
        assert (event.get("user"), event.get("src_ip"), event.get("auth_method")) == (
            "deploy",
            "192.0.2.60",
            "publickey",
        )

    def test_ambiguous_public_key_line_gets_no_source(self, tmp_path):
        # A certificate key ID is chosen by the client too.
        event = parse_line(
            tmp_path,
            "Failed publickey for invalid user bob from 198.51.100.66 port 58950 ssh2: "
            "ED25519-CERT SHA256:AAAA ID x from 192.0.2.10 port 1 ssh2: y (serial 0) CA ED25519",
        )
        assert event.get("action") == "ssh_failed_password"
        assert event.get("source_ambiguous") == "true"
        assert event.get("src_ip") is None

    def test_password_line_with_trailing_text_is_ambiguous(self, tmp_path):
        event = parse_line(
            tmp_path,
            "Failed password for invalid user test from 127.0.0.1 port 58946 ssh2: "
            "from 10.10.1.2 port 55555 ssh2 trailing",
        )
        assert event.get("source_ambiguous") == "true"
        assert event.get("src_ip") is None

    def test_invalid_user_takes_the_last_source(self, tmp_path):
        event = parse_line(
            tmp_path, "Invalid user a from 192.0.2.10 port 1 from 198.51.100.66 port 53000"
        )
        assert (event.get("user"), event.get("src_ip")) == (
            "a from 192.0.2.10 port 1",
            "198.51.100.66",
        )

    def test_accepted_key_information_is_ignored(self, tmp_path):
        event = parse_line(
            tmp_path,
            "Accepted publickey for deploy from 192.0.2.10 port 50122 ssh2: "
            "ED25519-CERT SHA256:AAAA ID x from 203.0.113.9 port 1 (serial 0) CA ED25519",
        )
        assert (event.get("user"), event.get("src_ip")) == ("deploy", "192.0.2.10")

    def test_line_without_source_has_no_action(self, tmp_path):
        event = parse_line(tmp_path, "Failed password for root from somewhere")
        assert event.get("action") is None


@pytest.mark.parametrize("program", ["sshd-session", "sshd-auth"])
def test_openssh_9_8_program_names(tmp_path, program):
    event = parse_line(
        tmp_path, "Failed password for root from 203.0.113.7 port 4242 ssh2", program=program
    )
    assert event.get("program") == program
    assert event.get("action") == "ssh_failed_password"
    assert authlog.is_auth_line(event.raw)


@pytest.mark.parametrize(
    "message",
    [
        "opsadmin : HOST=web01 ; TTY=pts/1 ; PWD=/home/opsadmin ; USER=root ; COMMAND=/bin/ls",
        "opsadmin : TTY=pts/1 ; CHROOT=/srv/jail ; PWD=/ ; USER=root ; COMMAND=/bin/ls",
    ],
)
def test_sudo_optional_fields(tmp_path, message):
    event = parse_line(tmp_path, message, program="sudo")
    assert event.get("action") == "sudo_command"
    assert event.get("target_user") == "root"


def test_sudo_failure_with_host_field(tmp_path):
    event = parse_line(
        tmp_path,
        "deploy : 3 incorrect password attempts ; HOST=web01 ; TTY=pts/0 ; PWD=/srv ; "
        "USER=root ; COMMAND=/bin/bash",
        program="sudo",
    )
    assert event.get("action") == "sudo_auth_failure"
    assert event.get("sudo_host") == "web01"


class TestRepeatedMessages:
    """rsyslog's "message repeated N times: [ ... ]" summary lines."""

    FAILED = "Failed password for root from 203.0.113.5 port 4242 ssh2"

    def test_each_repetition_becomes_an_event(self, tmp_path):
        log = tmp_path / "auth.log"
        log.write_text(
            f"Mar 10 09:00:00 web01 sshd[7]: {self.FAILED}\n"
            f"Mar 10 09:00:09 web01 sshd[7]: message repeated 5 times: [ {self.FAILED}]\n"
        )
        events = authlog.parse(log, year=2024).events
        assert len(events) == 6
        repeats = events[1:]
        assert {e.get("action") for e in repeats} == {"ssh_failed_password"}
        assert {e.get("src_ip") for e in repeats} == {"203.0.113.5"}
        assert {e.get("repeated") for e in repeats} == {"5"}
        assert repeats[0].origin == "auth.log:2 (repeat 1/5)"
        assert repeats[-1].origin == "auth.log:2 (repeat 5/5)"
        assert events[0].get("repeated") is None

    def test_unknown_inner_message_is_kept(self, tmp_path):
        log = tmp_path / "auth.log"
        log.write_text("Mar 10 09:00:00 web01 CRON[7]: message repeated 2 times: [ tick]\n")
        events = authlog.parse(log, year=2024).events
        assert [e.get("message") for e in events] == ["tick", "tick"]
        assert all(e.get("action") is None for e in events)

    def test_huge_count_is_capped(self, tmp_path):
        log = tmp_path / "auth.log"
        log.write_text(
            f"Mar 10 09:00:09 web01 sshd[7]: message repeated 3000000 times: [ {self.FAILED}]\n"
        )
        result = authlog.parse(log, year=2024)
        assert len(result.events) == authlog.MAX_REPEAT
        assert result.events[-1].origin == f"auth.log:1 (repeat {authlog.MAX_REPEAT}/3000000)"
        assert result.warnings == ["auth.log:1: repeat count 3000000 capped at 1000 events"]

    def test_zero_count_keeps_the_line(self, tmp_path):
        log = tmp_path / "auth.log"
        log.write_text(
            f"Mar 10 09:00:09 web01 sshd[7]: message repeated 0 times: [ {self.FAILED}]\n"
        )
        result = authlog.parse(log, year=2024)
        (event,) = result.events
        assert event.get("action") is None
        assert event.get("repeated") is None
        assert result.warnings == ["auth.log:1: repeat count of 0, line kept as is"]

    def test_not_a_summary_line(self, tmp_path):
        log = tmp_path / "auth.log"
        log.write_text("Mar 10 09:00:00 web01 app[7]: message repeated often: [x]\n")
        (event,) = authlog.parse(log, year=2024).events
        assert event.get("message") == "message repeated often: [x]"
