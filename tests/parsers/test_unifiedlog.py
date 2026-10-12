import json
from datetime import datetime
from pathlib import Path

import pytest

from vigie.parsers import unifiedlog
from vigie.timeutils import UTC

FIXTURES = Path(__file__).parent.parent / "fixtures" / "unifiedlog"


def record(message, process="/usr/libexec/syspolicyd", **extra):
    return json.dumps(
        {
            "eventType": "logEvent",
            "messageType": "Default",
            "processImagePath": process,
            "processID": 491,
            "userID": 0,
            "subsystem": "com.apple.syspolicy.exec",
            "category": "default",
            "timestamp": "2026-10-12 22:14:21.057424+0200",
            "eventMessage": message,
            **extra,
        }
    )


def parse(line):
    warnings = []
    return unifiedlog.parse_line(line, origin="test:1", warnings=warnings), warnings


def test_common_fields_and_timestamp():
    event, warnings = parse(record("Code evaluation completed: 2"))
    assert warnings == []
    assert event.source == "unifiedlog"
    assert event.timestamp == datetime(2026, 10, 12, 20, 14, 21, 57424, tzinfo=UTC)
    assert dict(event.fields) == {
        "process": "syspolicyd",
        "process_path": "/usr/libexec/syspolicyd",
        "pid": "491",
        "user_id": "0",
        "subsystem": "com.apple.syspolicy.exec",
        "category": "default",
        "message_type": "Default",
        "message": "Code evaluation completed: 2",
    }
    assert event.host is None
    assert event.origin == "test:1"


@pytest.mark.parametrize(
    "line",
    [
        "",
        'Filtering the log data using "process == \\"sudo\\""',
        '{"count":12,"finished":1}',
        json.dumps({"eventType": "timesyncEvent", "eventMessage": "=== system boot: 1234"}),
        json.dumps({"eventType": "signpostEvent", "eventMessage": "begin"}),
        "[1, 2]",
    ],
)
def test_lines_that_hold_no_log_message_are_skipped(line):
    assert parse(line) == (None, [])


def test_bad_lines_are_warnings():
    assert parse("not json") == (None, ["test:1: not a JSON object"])
    event, warnings = parse(record("x", timestamp="yesterday"))
    assert event is None
    assert warnings == ["test:1: invalid ISO 8601 timestamp: 'yesterday'"]


def test_sudo_and_sshd_messages_reuse_the_auth_log_parser():
    sudo, _ = parse(
        record(
            "   alice : 1 incorrect password attempt ; PWD=/tmp ; USER=root ; "
            "COMMAND=/usr/bin/true",
            process="/usr/bin/sudo",
        )
    )
    assert sudo.get("action") == "sudo_auth_failure"
    assert (sudo.get("user"), sudo.get("target_user")) == ("alice", "root")
    ssh, _ = parse(
        record(
            "Failed password for invalid user admin from 203.0.113.7 port 50000 ssh2",
            process="/usr/libexec/sshd-session",
        )
    )
    assert ssh.get("action") == "ssh_failed_password"
    assert (ssh.get("user"), ssh.get("src_ip")) == ("admin", "203.0.113.7")


def test_local_password_failure():
    uuid = "3F2A9C41-7B6D-4E8A-9D15-6C0B2E7A4F93"
    event, _ = parse(
        record(
            f"Authentication failed for <private> ({uuid}): ODErrorCredentialsInvalid",
            process="/usr/libexec/opendirectoryd",
        )
    )
    assert event.get("action") == "local_auth_failure"
    assert event.get("account_uuid") == uuid
    assert event.get("od_error") == "ODErrorCredentialsInvalid"
    assert event.get("user") is None  # redacted by macOS
    # With private data logging turned on, the name is there.
    named, _ = parse(
        record(
            f"Authentication failed for alice ({uuid}): ODErrorCredentialsInvalid",
            process="/usr/libexec/opendirectoryd",
        )
    )
    assert named.get("user") == "alice"


BTM = (
    "/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/"
    "Resources/backgroundtaskmanagementd"
)


def test_new_launch_item():
    event, _ = parse(
        record(
            "registerLaunchItem: result=no error, new item=uuid=3DC8E8D6-3A8A-41B9-890A-"
            "648E3AAA0B6B, name=Sync, Inc. agent, type=legacy agent, disposition=[enabled, "
            "allowed, not notified], identifier=8.com.example.sync, url=file:///Users/alice/"
            "Library/LaunchAgents/com.example.sync%20agent.plist",
            process=BTM,
        )
    )
    assert event.get("action") == "launch_item_added"
    assert event.get("item_name") == "Sync, Inc. agent"
    assert event.get("item_type") == "legacy agent"
    assert event.get("item_disposition") == "enabled, allowed, not notified"
    assert event.get("item_identifier") == "com.example.sync"  # without the type number
    assert (
        event.get("item_path") == "/Users/alice/Library/LaunchAgents/com.example.sync agent.plist"
    )


@pytest.mark.parametrize(
    "message",
    [
        "registerLaunchItem: result=invalid parameter, new item=(null)",
        "registerLaunchItem: uid=501, type=legacy agent, bundleURL=(null), url=<private>, "
        "config=<private>",
        "registerLaunchItem: found existing item: uuid=1, name=x, type=legacy agent, "
        "disposition=[enabled], identifier=8.x, url=file:///x.plist",
    ],
)
def test_other_launch_item_messages_have_no_action(message):
    event, _ = parse(record(message, process=BTM))
    assert event.get("action") is None


def test_gatekeeper_denial():
    event, _ = parse(
        record(
            "Adding Gatekeeper denial breadcrumb (direct): PST: (path: c802a60e17658a18), "
            "(team: (null)), (id: hello), (bundle_id: NOT_A_BUNDLE)"
        )
    )
    assert event.get("action") == "gatekeeper_denied"
    assert event.get("gk_check") == "direct"
    assert event.get("signing_id") == "hello"
    assert event.get("bundle_id") == "NOT_A_BUNDLE"
    assert event.get("team_id") is None


def test_bastion_bits_are_decoded():
    event, _ = parse(
        record("Got bastion violation 0x80000400801 path <private> responsible path: x")
    )
    assert event.get("action") == "xprotect_behavior"
    assert event.get("bastion_mask") == "0x80000400801"
    assert event.get("signature") == (
        "macOS.Browser.Generic",
        "macOS.InfoStealer.Generic",
        "macOS.Persistence.Launchplists",
        "unknown-0x80000000000",
    )


def test_bastion_signatures():
    assert unifiedlog.bastion_signatures(0x400000) == ("macOS.Persistence.Launchplists",)
    assert unifiedlog.bastion_signatures(0) == ()


def test_parse_fixture_file():
    result = unifiedlog.parse(FIXTURES / "mac_ssh.ndjson")
    assert result.warnings == []
    assert len(result.events) == 14
    assert result.events[0].origin == "mac_ssh.ndjson:2"


def test_predicate_covers_the_actions_rules_use():
    for process in ("sshd", "sudo", "opendirectoryd", "backgroundtaskmanagementd", "syspolicyd"):
        assert f'"{process}"' in unifiedlog.PREDICATE
    for start in ("Authentication failed for", "Adding Gatekeeper denial", "Got bastion violation"):
        assert start in unifiedlog.PREDICATE


def test_readme_export_command_uses_the_predicate():
    readme = (Path(__file__).parents[2] / "README.md").read_text(encoding="utf-8")
    assert f"--predicate '{unifiedlog.PREDICATE}'" in readme
