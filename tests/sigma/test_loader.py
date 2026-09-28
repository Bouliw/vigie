import pytest

from vigie.sigma.loader import load_rules, parse_rule
from vigie.sigma.matcher import SigmaError

LSASS_RULE = """
    title: LSASS Access
    id: 0b3a4c1e-0000-4000-8000-000000000001
    name: lsass_access
    status: test
    description: |
      A process opened a handle to LSASS.
    author: Vigie
    date: 2024-03-10
    references: https://attack.mitre.org/techniques/T1003/001/
    tags:
      - attack.credential-access
      - attack.T1003.001
    logsource:
      product: windows
      service: sysmon
    detection:
      selection:
        EventID: 10
        TargetImage|endswith: '\\lsass.exe'
      filter:
        SourceImage|endswith: '\\MsMpEng.exe'
      condition: selection and not filter
    falsepositives:
      - Security products
    level: High
"""


def test_license_is_kept(rule_doc):
    document = rule_doc(LSASS_RULE)
    document["license"] = "DRL-1.1"
    assert parse_rule(document).meta.license == "DRL-1.1"


def test_parse_rule_metadata(rule_doc):
    rule = parse_rule(rule_doc(LSASS_RULE), "rules/lsass.yml")
    meta = rule.meta
    assert meta.id == "0b3a4c1e-0000-4000-8000-000000000001"
    assert meta.title == "LSASS Access"
    assert meta.name == "lsass_access"
    assert meta.level == "high"
    assert meta.kind == "detection"
    assert meta.description == "A process opened a handle to LSASS."
    assert meta.date == "2024-03-10"
    assert meta.references == ("https://attack.mitre.org/techniques/T1003/001/",)
    assert meta.tags == ("attack.credential-access", "attack.t1003.001")
    assert meta.falsepositives == ("Security products",)
    assert meta.path == "rules/lsass.yml"
    assert meta.license == ""
    assert rule.sources == {"sysmon"}
    assert set(rule.selections) == {"selection", "filter"}


def test_rule_matches_events(rule_doc, make_event):
    rule = parse_rule(rule_doc(LSASS_RULE))
    hit = make_event(
        "sysmon", event_id=10, EventID="10", TargetImage="C:\\Windows\\system32\\lsass.exe"
    )
    filtered = make_event(
        "sysmon",
        event_id=10,
        EventID="10",
        TargetImage="C:\\Windows\\system32\\lsass.exe",
        SourceImage="C:\\ProgramData\\Defender\\MsMpEng.exe",
    )
    wrong_source = make_event(
        "security", event_id=10, EventID="10", TargetImage="C:\\Windows\\system32\\lsass.exe"
    )
    assert rule.matches(hit)
    assert not rule.matches(filtered)
    assert not rule.matches(wrong_source)


def test_rule_uses_target_aliases(rule_doc, make_event):
    rule = parse_rule(
        rule_doc(
            """
            title: Bitsadmin Download
            level: medium
            logsource: {product: windows, category: process_creation}
            detection:
              selection:
                Image|endswith: '\\bitsadmin.exe'
                CommandLine|contains: /transfer
              condition: selection
            """
        )
    )
    sysmon = make_event(
        "sysmon", event_id=1, Image="C:\\Windows\\bitsadmin.exe", CommandLine="x /transfer y"
    )
    security = make_event(
        "security",
        event_id=4688,
        NewProcessName="C:\\Windows\\bitsadmin.exe",
        CommandLine="x /transfer y",
    )
    assert rule.matches(sysmon)
    assert rule.matches(security)


def test_missing_id_falls_back_to_title(rule_doc):
    rule = parse_rule(
        rule_doc(
            """
            title: No Id
            level: low
            logsource: {product: linux, service: auth}
            detection: {keywords: [x], condition: keywords}
            """
        )
    )
    assert rule.meta.id == "No Id"
    assert rule.meta.tags == ()


BASE = {
    "title": "T",
    "level": "low",
    "logsource": {"product": "linux", "service": "auth"},
    "detection": {"sel": {"program": "sshd"}, "condition": "sel"},
}


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"title": ""}, "missing or empty title"),
        ({"title": None}, "missing or empty title"),
        ({"level": "severe"}, "level must be one of"),
        ({"level": None}, "level must be one of"),
        ({"logsource": {"product": "macos"}}, "unsupported logsource"),
        ({"detection": None}, "detection must be a mapping with a condition"),
        ({"detection": {"sel": {"a": 1}}}, "detection must be a mapping with a condition"),
        ({"detection": {"condition": "sel"}}, "defines no selection"),
        ({"detection": {"sel": {"a": 1}, "condition": "other"}}, "unknown selection"),
        (
            {"detection": {"sel": {"a": 1}, "timeframe": "5m", "condition": "sel"}},
            "timeframe",
        ),
        ({"tags": {"a": 1}}, "'tags' must be a string or a list"),
        ({"action": "global"}, "rule collections"),
    ],
)
def test_invalid_rules(changes, message):
    document = {**BASE, **changes}
    with pytest.raises(SigmaError, match=message):
        parse_rule(document)


def test_rule_must_be_a_mapping():
    with pytest.raises(SigmaError, match="YAML mapping"):
        parse_rule(["not", "a", "rule"])


def test_load_rules_from_folder(write_rules):
    folder = write_rules(
        **{
            "windows/lsass.yml": LSASS_RULE,
            "linux/ssh.yaml": """
                title: SSH Failure
                level: low
                logsource: {product: linux, service: sshd}
                detection:
                  selection: {action: ssh_failed_password}
                  condition: selection
            """,
            "notes.txt": "not a rule",
        }
    )
    ruleset = load_rules(folder)
    assert ruleset.errors == []
    assert [rule.meta.title for rule in ruleset.detections] == ["SSH Failure", "LSASS Access"]


def test_bad_rules_are_reported_not_raised(write_rules):
    folder = write_rules(
        **{
            # Files load in path order: the first rule with an id wins.
            "a_good.yml": LSASS_RULE,
            "broken.yml": "title: [unclosed",
            "unsupported.yml": """
                title: DNS Server Rule
                level: low
                logsource: {product: windows, service: dns-server}
                detection: {sel: {a: 1}, condition: sel}
            """,
            "z_duplicate.yml": LSASS_RULE.replace("LSASS Access", "Copy"),
            "multi.yml": """
                title: First
                level: low
                logsource: {product: linux, service: auth}
                detection: {sel: {a: 1}, condition: sel}
                ---
                title: Second
                level: nope
                ---
            """,
        }
    )
    ruleset = load_rules(folder)
    assert sorted(rule.meta.title for rule in ruleset.detections) == ["First", "LSASS Access"]
    errors = sorted(error.replace(str(folder) + "/", "") for error in ruleset.errors)
    assert errors[0].startswith("broken.yml: cannot read rule file")
    assert errors[1:] == [
        "multi.yml (document 2) [Second]: level must be one of "
        "informational, low, medium, high, critical",
        "unsupported.yml [DNS Server Rule]: unsupported logsource "
        "(product: windows, service: dns-server)",
        "z_duplicate.yml [Copy]: duplicate rule id or name 0b3a4c1e-0000-4000-8000-000000000001",
    ]


def test_load_single_file_and_list(write_rules):
    folder = write_rules(**{"a.yml": LSASS_RULE})
    assert len(load_rules(folder / "a.yml").detections) == 1
    assert len(load_rules([str(folder / "a.yml")]).detections) == 1


def test_missing_file_is_an_error(tmp_path):
    ruleset = load_rules(tmp_path / "missing.yml")
    assert ruleset.detections == []
    assert "cannot read rule file" in ruleset.errors[0]
