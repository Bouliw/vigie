import shutil
from pathlib import Path

import pytest

from vigie.collect import collect
from vigie.sigma.engine import Engine
from vigie.sigma.loader import load_rules

FIXTURES = Path(__file__).parent.parent / "fixtures"

RULES = {
    "lsass.yml": """
        title: LSASS Memory Access
        id: test-lsass
        level: high
        logsource: {product: windows, category: process_access}
        detection:
          selection:
            TargetImage|endswith: '\\lsass.exe'
            GrantedAccess: '0x1010'
          condition: selection
    """,
    "bits.yml": """
        title: Bitsadmin Transfer
        id: test-bits
        level: medium
        logsource: {product: windows, category: process_creation}
        detection:
          selection:
            Image|endswith: '\\bitsadmin.exe'
            CommandLine|contains|all: [/transfer, http]
          condition: selection
    """,
    "cleared.yml": """
        title: Security Log Cleared
        id: test-1102
        level: high
        logsource: {product: windows, service: security}
        detection:
          selection: {EventID: 1102}
          condition: selection
    """,
    "useradd.yml": """
        title: Local User Created
        id: test-useradd
        level: low
        logsource: {product: linux, service: auth}
        detection:
          selection: {action: user_created}
          condition: selection
    """,
}


LOGS = [
    "authlog/auth.log",
    "evtx/DE_1102_security_log_cleared.evtx",
    "evtx/sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx",
    "winjson/cmd_bitsadmin_download_psh_script_excerpt.json",
]


@pytest.fixture
def logs(tmp_path):
    folder = tmp_path / "logs"
    for relative in LOGS:
        target = folder / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(FIXTURES / relative, target)
    return folder


def test_engine_on_fixture_logs(write_rules, logs):
    ruleset = load_rules(write_rules(**RULES))
    assert ruleset.errors == []
    events = collect(logs, year=2024).events
    alerts = Engine(ruleset).run(events)

    fired = [(alert.rule.id, alert.events[0].origin) for alert in alerts]
    # Most severe first, then chronological: the 1102 (2019-03-19) comes after
    # the LSASS access (2019-03-17) because both are "high".
    assert fired == [
        ("test-lsass", "sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx#4807"),
        ("test-1102", "DE_1102_security_log_cleared.evtx#452811"),
        # The same process_creation rule fires on Sysmon 1 and on Security 4688.
        ("test-bits", "cmd_bitsadmin_download_psh_script_excerpt.json:1"),
        ("test-bits", "cmd_bitsadmin_download_psh_script_excerpt.json:5"),
        ("test-useradd", "auth.log:23"),
    ]


def test_alert_holds_its_event(write_rules, make_event):
    ruleset = load_rules(write_rules(**{"useradd.yml": RULES["useradd.yml"]}))
    event = make_event("auth", action="user_created", user="svc_update")
    (alert,) = Engine(ruleset).run([event, make_event("auth", action="ssh_accepted")])
    assert alert.events == (event,)
    assert alert.timestamp == event.timestamp == alert.last_seen
    assert dict(alert.group) == {}


def test_no_rules_no_alerts(make_event):
    ruleset = load_rules([])
    assert Engine(ruleset).run([make_event()]) == []
