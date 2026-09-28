"""Every rule shipped with Vigie is tested here.

* metadata: ids, required fields, ATT&CK tags that exist in the bundled
  release, and the attribution the Detection Rule License requires for rules
  adapted from SigmaHQ;
* behaviour: each rule fires exactly as expected on its positive fixtures,
  never on its negative ones, and never on any other fixture of the repository.
"""

from __future__ import annotations

import re
import uuid
from datetime import date, timedelta
from functools import cache
from pathlib import Path

import pytest
import yaml

from vigie.attack import default_attack_data
from vigie.attack.mapping import OTHER_ATTACK_TAG, TECHNIQUE_TAG
from vigie.collect import collect
from vigie.models import LEVELS
from vigie.rules import RULES_DIR
from vigie.sigma.correlation import CorrelationRule
from vigie.sigma.engine import Engine, Evaluation
from vigie.sigma.loader import DetectionRule, load_rules

FIXTURES = Path(__file__).parent.parent / "fixtures"
CASES = yaml.safe_load((Path(__file__).parent / "cases.yaml").read_text(encoding="utf-8"))
RULE_FILES = sorted(RULES_DIR.rglob("*.yml"))
# Every file of the fixture folder that Vigie reads, whatever its name.
LOG_FIXTURES = sorted(report.path for report in collect(FIXTURES, year=2024).files)
SIGMAHQ_BLOB = "https://github.com/SigmaHQ/sigma/blob/"
SIGMAHQ_COMMIT = "07ec293a51695cb1131a2e05260247872b31e1e1"

# The parameters that give each correlation its meaning. Public data has too few
# near misses to pin them all through fixtures, so they are pinned here: changing
# one must be a deliberate decision, made in the rule and in this table.
CORRELATIONS = {
    # SSH Brute Force
    "44043ef0-67f0-4380-9c98-b348be632e58": ("event_count", ("src_ip",), timedelta(minutes=5), 10),
    # SSH Password Spraying (distinct user names)
    "a5668195-278b-4b24-aaf9-53ee8ff41701": ("value_count", ("src_ip",), timedelta(minutes=10), 5),
    # SSH Login After Brute Force
    "156d0b6d-aea1-479c-91ce-eaf6c08cfa67": (
        "temporal_ordered",
        ("src_ip",),
        timedelta(minutes=10),
        0,
    ),
    # Windows Logon Brute Force From Single Source
    "6cf25939-c0a0-43f8-bb43-34d254f459cb": (
        "event_count",
        ("IpAddress", "WorkstationName"),
        timedelta(minutes=1),
        5,
    ),
    # Kerberos Password Spraying From Single Source (distinct TargetUserName)
    "bf0ebcbf-b7ab-4600-8558-54ec2de7b272": (
        "value_count",
        ("IpAddress",),
        timedelta(minutes=10),
        5,
    ),
}
# Rules that only feed correlations and must never raise alerts of their own.
FEEDER_RULES = {
    "73004885-6e82-4146-ab6a-1b834d099ee5",  # SSH Failed Password
    "118338f6-e0cd-41d4-bfdf-58a76f7ba286",  # Windows Failed Logon
    "0ca0b8d2-4007-47d0-81ec-8c96d0fc2cf1",  # Kerberos Authentication Failure
}


@cache
def ruleset():
    return load_rules(RULES_DIR)


@cache
def rules_by_id() -> dict[str, DetectionRule | CorrelationRule]:
    rules = ruleset()
    return {rule.meta.id: rule for rule in [*rules.detections, *rules.correlations]}


@cache
def evaluate(fixture: str) -> Evaluation:
    events = collect(FIXTURES / fixture, year=2024).events
    return Engine(ruleset()).evaluate(events)


def count(rule_id: str, fixture: str) -> int:
    """Events matched by a detection rule, or alerts raised by a correlation."""
    evaluation = evaluate(fixture)
    if isinstance(rules_by_id()[rule_id], CorrelationRule):
        return len(evaluation.correlation_alerts.get(rule_id, []))
    return len(evaluation.matches.get(rule_id, []))


def expected_positives() -> dict[tuple[str, str], int]:
    return {
        (case["rule"], positive["fixture"]): positive["expected"]
        for case in CASES
        for positive in case.get("positive", [])
    }


def positive_params():
    return [
        pytest.param(rule_id, fixture, expected, id=f"{rule_id[:8]}-{fixture}")
        for (rule_id, fixture), expected in expected_positives().items()
    ]


def negative_params():
    return [
        pytest.param(
            case["rule"], negative["fixture"], id=f"{case['rule'][:8]}-{negative['fixture']}"
        )
        for case in CASES
        for negative in case.get("negative", [])
    ]


def documents(path: Path) -> list[dict]:
    return [doc for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")) if doc]


# --- The rule set as a whole ---------------------------------------------------


def test_rules_load_without_errors():
    rules = ruleset()
    assert rules.errors == []
    assert len(rules.detections) + len(rules.correlations) == len(RULE_FILES)


def test_every_rule_has_positive_and_negative_cases():
    case_ids = [case["rule"] for case in CASES]
    assert len(case_ids) == len(set(case_ids)), "a rule appears twice in cases.yaml"
    assert set(case_ids) == set(rules_by_id())
    for case in CASES:
        assert case.get("positive"), f"{case['rule']} has no positive case"
        assert case.get("negative"), f"{case['rule']} has no negative case"


def test_case_fixtures_exist():
    for case in CASES:
        for item in [*case.get("positive", []), *case.get("negative", [])]:
            assert (FIXTURES / item["fixture"]).is_file(), item["fixture"]


def test_cases_are_well_formed():
    for case in CASES:
        assert set(case) <= {"rule", "positive", "negative"}, case["rule"]
        items = [*case.get("positive", []), *case.get("negative", [])]
        fixtures = [item["fixture"] for item in items]
        assert len(fixtures) == len(set(fixtures)), f"{case['rule']} lists a fixture twice"
        for item in case.get("positive", []):
            assert set(item) == {"fixture", "expected"}, item
        for item in case.get("negative", []):
            assert set(item) == {"fixture"}, item


def test_feeder_rules_stay_hidden():
    """Rules that only feed a correlation must not flood the report with their own alerts."""
    assert ruleset().hidden_rule_ids() == FEEDER_RULES


def test_correlation_parameters():
    rules = {rule.meta.id: rule for rule in ruleset().correlations}
    assert rules.keys() == CORRELATIONS.keys(), "pin the parameters of every correlation"
    for rule_id, expected in CORRELATIONS.items():
        rule = rules[rule_id]
        assert (rule.type, rule.group_by, rule.timespan, rule.threshold) == expected, rule_id


@pytest.mark.parametrize(
    ("rule_id", "fixture"),
    [
        ("6cf25939-c0a0-43f8-bb43-34d254f459cb", "winjson/purplesharp_ad_playbook_I_excerpt.json"),
        ("bf0ebcbf-b7ab-4600-8558-54ec2de7b272", "evtx/kerberos_pwd_spray_4771.evtx"),
    ],
)
def test_correlation_threshold_on_public_events(rule_id, fixture):
    """Replay the first events of the only public bursts: one short of the threshold, then exact.

    The events are the unmodified public ones, only fewer of them.
    """
    threshold = rules_by_id()[rule_id].threshold
    (base,) = base_rules(rule_id)
    fed = [event for event in collect(FIXTURES / fixture, year=2024).events if base.matches(event)]
    engine = Engine(ruleset())
    assert engine.evaluate(fed[: threshold - 1]).correlation_alerts[rule_id] == []
    assert len(engine.evaluate(fed[:threshold]).correlation_alerts[rule_id]) == 1


# --- Behaviour on fixtures -------------------------------------------------------


@pytest.mark.parametrize(("rule_id", "fixture", "expected"), positive_params())
def test_positive_case(rule_id, fixture, expected):
    assert expected > 0
    assert count(rule_id, fixture) == expected


@pytest.mark.parametrize(("rule_id", "fixture"), negative_params())
def test_negative_case(rule_id, fixture):
    assert count(rule_id, fixture) == 0


@pytest.mark.parametrize(("rule_id", "fixture"), negative_params())
def test_negative_case_exercises_the_rule(rule_id, fixture):
    """A negative only proves something if the rule saw events of its log source.

    This checks routing only (source, category EventIDs, program): whether the
    fixture holds a real near miss is explained next to each case in cases.yaml.
    """
    targets = [target for rule in base_rules(rule_id) for target in rule.targets]
    events = collect(FIXTURES / fixture, year=2024).events
    assert any(target.accepts(event) for target in targets for event in events)


@pytest.mark.parametrize("fixture", LOG_FIXTURES)
def test_no_rule_fires_where_it_should_not(fixture):
    expected = expected_positives()
    unexpected = {
        rules_by_id()[rule_id].meta.title: found
        for rule_id in rules_by_id()
        if (found := count(rule_id, fixture)) != expected.get((rule_id, fixture), 0)
    }
    assert unexpected == {}


def base_rules(rule_id: str) -> list[DetectionRule]:
    """The detection rules a rule ultimately depends on."""
    rule = rules_by_id()[rule_id]
    if isinstance(rule, DetectionRule):
        return [rule]
    references = ruleset().references
    return [base for ref in rule.rules for base in base_rules(references[ref])]


# --- Metadata of each rule file ------------------------------------------------


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda p: p.name)
def test_rule_file_metadata(path):
    assert re.fullmatch(r"(win|lnx)_[a-z0-9_]+\.yml", path.name)
    assert path.parent.name == {"win": "windows", "lnx": "linux"}[path.name[:3]]
    (doc,) = documents(path)  # one rule per file

    assert uuid.UUID(doc["id"]).version == 4
    assert doc["status"] in ("experimental", "test", "stable")
    assert doc["level"] in LEVELS
    for key in ("title", "description", "author"):
        assert isinstance(doc.get(key), str) and doc[key].strip(), key
    assert isinstance(doc.get("date"), date)
    assert doc.get("references"), "at least one reference"
    assert doc.get("falsepositives"), "at least one false positive"
    if "correlation" not in doc:
        assert (
            doc["logsource"].get("product")
            == {"windows": "windows", "linux": "linux"}[path.parent.name]
        )


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda p: p.name)
def test_rule_attack_tags(path):
    (doc,) = documents(path)
    mapping = default_attack_data().map_tags(doc.get("tags", []))
    assert mapping.techniques, "at least one ATT&CK technique"
    assert mapping.unknown == ()
    assert mapping.revoked == (), "use current ATT&CK ids"
    # Tactic tags are compared as written: only ATT&CK 19.2 shortnames, so a legacy
    # "defense-evasion" or a "credential_access" spelling is rejected.
    tagged_tactics = {
        value
        for tag in doc["tags"]
        if tag.startswith("attack.")
        and not TECHNIQUE_TAG.match(value := tag.removeprefix("attack."))
        and not OTHER_ATTACK_TAG.match(value)
    }
    technique_tactics = {tactic.shortname for tactic in mapping.tactics}
    assert tagged_tactics, "tag the tactic too"
    assert tagged_tactics <= technique_tactics, "tactic tags must belong to the techniques"


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda p: p.name)
def test_rule_attribution(path):
    """Rules adapted from SigmaHQ must follow the Detection Rule License 1.1."""
    (doc,) = documents(path)
    derived = [item for item in doc.get("related", []) if item.get("type") == "derived"]
    sigmahq_links = [ref for ref in doc.get("references", []) if ref.startswith(SIGMAHQ_BLOB)]
    if not derived and doc.get("license") is None and not sigmahq_links:
        return
    assert derived, "a rule based on SigmaHQ must list the rules it derives from"
    assert doc.get("license") == "DRL-1.1"
    assert doc["author"].endswith(" (SigmaHQ), adapted by Bouliw"), "keep the original authors"
    assert all(link.startswith(f"{SIGMAHQ_BLOB}{SIGMAHQ_COMMIT}/") for link in sigmahq_links), (
        "link the SigmaHQ rules at the pinned commit"
    )
    # Project convention: one link per derived rule.
    assert len(sigmahq_links) == len(derived)
    assert isinstance(doc.get("modified"), date)
