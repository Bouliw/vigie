from datetime import timedelta
from pathlib import Path

import pytest

from vigie.collect import collect
from vigie.models import Alert, RuleMeta
from vigie.sigma.correlation import (
    CorrelationRule,
    Occurrence,
    correlate,
    parse_correlation,
    parse_timespan,
)
from vigie.sigma.engine import Engine
from vigie.sigma.loader import load_rules
from vigie.sigma.matcher import SigmaError

FIXTURES = Path(__file__).parent.parent / "fixtures"
META = RuleMeta(id="corr", title="Correlation", level="high", kind="correlation")


def correlation(**section):
    return parse_correlation({"correlation": section}, META)


@pytest.fixture
def occurrence(make_event):
    def make(seconds, **fields):
        return Occurrence.from_event(make_event("auth", seconds=seconds, **fields))

    return make


class TestParsing:
    def test_event_count(self):
        rule = correlation(
            type="event_count",
            rules="ssh_failed",
            **{"group-by": "src_ip"},
            timespan="5m",
            condition={"gte": 10},
        )
        assert rule.rules == ("ssh_failed",)
        assert rule.group_by == ("src_ip",)
        assert rule.timespan == timedelta(minutes=5)
        assert rule.threshold == 10
        assert rule.generate is False

    def test_gt_means_one_more(self):
        rule = correlation(type="event_count", rules=["a"], timespan="1h", condition={"gt": 9})
        assert rule.threshold == 10

    def test_value_count_field_and_aliases(self):
        rule = correlation(
            type="value_count",
            rules=["a", "b"],
            **{"group-by": ["ip"]},
            timespan="10m",
            condition={"gte": 3, "field": "user"},
            aliases={"ip": {"a": "src_ip", "b": "IpAddress"}},
            generate=True,
        )
        assert rule.value_field == "user"
        assert rule.field_for("ip", "b") == "IpAddress"
        assert rule.field_for("user", "a") == "user"
        assert rule.generate is True

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("30s", timedelta(seconds=30)),
            ("5m", timedelta(minutes=5)),
            ("1h", timedelta(hours=1)),
            ("2d", timedelta(days=2)),
            ("1w", timedelta(weeks=1)),
        ],
    )
    def test_timespan(self, text, expected):
        assert parse_timespan(text) == expected

    @pytest.mark.parametrize("text", ["5", "5 minutes", "0m", "-5m", "5y", None, ""])
    def test_invalid_timespan(self, text):
        with pytest.raises(SigmaError, match="invalid timespan"):
            parse_timespan(text)

    @pytest.mark.parametrize(
        ("section", "message"),
        [
            ({"type": "count"}, "type must be one of"),
            ({"type": "event_count", "rules": []}, "must not be empty"),
            ({"type": "event_count", "rules": [1]}, "rules must be a string or a list"),
            ({"type": "temporal", "rules": ["a"], "timespan": "5m"}, "at least two rules"),
            ({"type": "event_count", "rules": ["a"], "timespan": "5m"}, "needs a condition"),
            (
                {"type": "event_count", "rules": ["a"], "timespan": "5m", "condition": {"lt": 3}},
                "only a single 'gt' or 'gte'",
            ),
            (
                {
                    "type": "event_count",
                    "rules": ["a"],
                    "timespan": "5m",
                    "condition": {"gte": 3, "lte": 9},
                },
                "only a single 'gt' or 'gte'",
            ),
            (
                {"type": "event_count", "rules": ["a"], "timespan": "5m", "condition": {"gte": 0}},
                "positive integer",
            ),
            (
                {
                    "type": "event_count",
                    "rules": ["a"],
                    "timespan": "5m",
                    "condition": {"gte": "3"},
                },
                "positive integer",
            ),
            (
                {
                    "type": "event_count",
                    "rules": ["a"],
                    "timespan": "5m",
                    "condition": {"gte": 3, "field": "user"},
                },
                "only applies to value_count",
            ),
            (
                {"type": "value_count", "rules": ["a"], "timespan": "5m", "condition": {"gte": 3}},
                "needs condition.field",
            ),
            (
                {
                    "type": "temporal",
                    "rules": ["a", "b"],
                    "timespan": "5m",
                    "condition": {"gte": 2},
                },
                "does not take a condition",
            ),
            (
                {"type": "temporal", "rules": ["a", "b"], "timespan": "5m", "aliases": ["x"]},
                "aliases must be a mapping",
            ),
            (
                {
                    "type": "temporal",
                    "rules": ["a", "b"],
                    "timespan": "5m",
                    "aliases": {"ip": "src_ip"},
                },
                "must map rule references",
            ),
            (
                {
                    "type": "temporal",
                    "rules": ["a", "b"],
                    "timespan": "5m",
                    "aliases": {"ip": {"c": "src_ip"}},
                },
                "not in the correlation",
            ),
            (
                {"type": "temporal", "rules": ["a", "b"], "timespan": "5m", "generate": "yes"},
                "generate must be true or false",
            ),
            (
                {"type": "temporal", "rules": ["a", "b"], "timespan": "5m", "group-by": [1]},
                "group-by must be",
            ),
        ],
    )
    def test_invalid(self, section, message):
        with pytest.raises(SigmaError, match=message):
            correlation(**section)

    def test_section_must_be_a_mapping(self):
        with pytest.raises(SigmaError, match="correlation must be a mapping"):
            parse_correlation({"correlation": "event_count"}, META)


def rule(kind, rules, threshold=0, value_field=None, group_by=("src_ip",), minutes=5):
    return CorrelationRule(
        meta=META,
        type=kind,
        rules=tuple(rules),
        group_by=tuple(group_by),
        timespan=timedelta(minutes=minutes),
        threshold=threshold,
        value_field=value_field,
    )


class TestEventCount:
    def test_burst_fires_once(self, occurrence):
        failures = [occurrence(7 * i, src_ip="203.0.113.45") for i in range(12)]
        (alert,) = correlate(rule("event_count", ["fail"], threshold=10), {"fail": failures})
        assert len(alert.events) == 10
        assert dict(alert.group) == {"src_ip": "203.0.113.45"}
        assert alert.rule is META

    def test_counts_per_group(self, occurrence):
        inputs = {
            "fail": [occurrence(i, src_ip="203.0.113.45") for i in range(3)]
            + [occurrence(i, src_ip="198.51.100.7") for i in range(3)]
        }
        alerts = correlate(rule("event_count", ["fail"], threshold=3), inputs)
        assert sorted(alert.group["src_ip"] for alert in alerts) == [
            "198.51.100.7",
            "203.0.113.45",
        ]

    def test_slow_attempts_stay_below_threshold(self, occurrence):
        # One attempt per minute never puts 10 attempts in a 5-minute window.
        slow = [occurrence(60 * i, src_ip="203.0.113.45") for i in range(30)]
        assert correlate(rule("event_count", ["fail"], threshold=10), {"fail": slow}) == []

    def test_window_boundary_is_inclusive(self, occurrence):
        pair = [occurrence(0, src_ip="a"), occurrence(300, src_ip="a")]
        assert len(correlate(rule("event_count", ["fail"], threshold=2), {"fail": pair})) == 1
        late = [occurrence(0, src_ip="a"), occurrence(301, src_ip="a")]
        assert correlate(rule("event_count", ["fail"], threshold=2), {"fail": late}) == []

    def test_long_attack_fires_per_burst(self, occurrence):
        failures = [occurrence(i, src_ip="a") for i in range(25)]
        alerts = correlate(rule("event_count", ["fail"], threshold=10), {"fail": failures})
        assert [len(alert.events) for alert in alerts] == [10, 10]

    def test_events_without_group_value_are_ignored(self, occurrence):
        inputs = {"fail": [occurrence(i) for i in range(5)]}
        assert correlate(rule("event_count", ["fail"], threshold=2), inputs) == []

    def test_no_group_by_counts_everything(self, occurrence):
        inputs = {"fail": [occurrence(i, src_ip=str(i)) for i in range(3)]}
        (alert,) = correlate(rule("event_count", ["fail"], threshold=3, group_by=()), inputs)
        assert dict(alert.group) == {}

    def test_several_referenced_rules_are_pooled(self, occurrence):
        inputs = {
            "ssh": [occurrence(0, src_ip="a"), occurrence(1, src_ip="a")],
            "sudo": [occurrence(2, src_ip="a")],
        }
        (alert,) = correlate(rule("event_count", ["ssh", "sudo"], threshold=3), inputs)
        assert len(alert.events) == 3


class TestValueCount:
    def test_many_distinct_users(self, occurrence):
        users = ["root", "admin", "root", "oracle", "test", "root", "ubuntu"]
        inputs = {"fail": [occurrence(i, src_ip="a", user=u) for i, u in enumerate(users)]}
        (alert,) = correlate(rule("value_count", ["fail"], threshold=5, value_field="user"), inputs)
        assert len(alert.events) == 7

    def test_same_user_repeated_does_not_count(self, occurrence):
        inputs = {"fail": [occurrence(i, src_ip="a", user="root") for i in range(20)]}
        assert (
            correlate(rule("value_count", ["fail"], threshold=2, value_field="user"), inputs) == []
        )


class TestTemporal:
    def test_any_order_within_window(self, occurrence):
        inputs = {"b": [occurrence(0, src_ip="a")], "a": [occurrence(60, src_ip="a")]}
        (alert,) = correlate(rule("temporal", ["a", "b"]), inputs)
        assert len(alert.events) == 2

    def test_too_far_apart(self, occurrence):
        inputs = {"a": [occurrence(0, src_ip="a")], "b": [occurrence(600, src_ip="a")]}
        assert correlate(rule("temporal", ["a", "b"]), inputs) == []

    def test_one_rule_alone_is_not_enough(self, occurrence):
        inputs = {"a": [occurrence(i, src_ip="a") for i in range(5)]}
        assert correlate(rule("temporal", ["a", "b"]), inputs) == []


class TestTemporalOrdered:
    def test_in_order(self, occurrence):
        inputs = {"fail": [occurrence(0, src_ip="a")], "success": [occurrence(30, src_ip="a")]}
        (alert,) = correlate(rule("temporal_ordered", ["fail", "success"]), inputs)
        assert [event.timestamp.second for event in alert.events] == [0, 30]

    def test_wrong_order(self, occurrence):
        inputs = {"fail": [occurrence(30, src_ip="a")], "success": [occurrence(0, src_ip="a")]}
        assert correlate(rule("temporal_ordered", ["fail", "success"]), inputs) == []

    def test_too_late(self, occurrence):
        inputs = {"fail": [occurrence(0, src_ip="a")], "success": [occurrence(301, src_ip="a")]}
        assert correlate(rule("temporal_ordered", ["fail", "success"]), inputs) == []

    def test_latest_start_is_kept(self, occurrence):
        # An old failure expires, a newer one still allows the sequence.
        inputs = {
            "fail": [occurrence(0, src_ip="a"), occurrence(250, src_ip="a")],
            "success": [occurrence(400, src_ip="a")],
        }
        (alert,) = correlate(rule("temporal_ordered", ["fail", "success"]), inputs)
        assert [event.timestamp.second for event in alert.events] == [10, 40]  # 250 s, 400 s

    def test_three_steps(self, occurrence):
        inputs = {
            "a": [occurrence(0, src_ip="x")],
            "b": [occurrence(10, src_ip="x")],
            "c": [occurrence(5, src_ip="x"), occurrence(20, src_ip="x")],
        }
        (alert,) = correlate(rule("temporal_ordered", ["a", "b", "c"]), inputs)
        assert len(alert.events) == 3

    def test_repeated_rule_needs_two_occurrences(self, occurrence):
        once = {"a": [occurrence(0, src_ip="x")], "b": [occurrence(10, src_ip="x")]}
        assert correlate(rule("temporal_ordered", ["a", "b", "a"]), once) == []
        twice = {
            "a": [occurrence(0, src_ip="x"), occurrence(20, src_ip="x")],
            "b": [occurrence(10, src_ip="x")],
        }
        (alert,) = correlate(rule("temporal_ordered", ["a", "b", "a"]), twice)
        assert len(alert.events) == 3


def test_occurrence_from_alert(make_event):
    events = (make_event(seconds=0), make_event(seconds=90))
    alert = Alert(META, events, {"src_ip": "a"})
    occurrence = Occurrence.from_alert(alert)
    assert occurrence.timestamp == events[1].timestamp
    assert occurrence.value("src_ip") == "a"
    assert occurrence.value("missing") is None


def test_multi_valued_field_is_not_a_group(make_event):
    occurrence = Occurrence.from_event(make_event(Data=("a", "b")))
    assert occurrence.value("Data") is None


SSH_RULES = {
    "ssh_failed.yml": """
        title: SSH Failed Password
        id: ssh-failed
        name: ssh_failed_password
        level: low
        logsource: {product: linux, service: sshd}
        detection:
          selection: {action: ssh_failed_password}
          condition: selection
    """,
    "ssh_accepted.yml": """
        title: SSH Login Accepted
        id: ssh-accepted
        name: ssh_accepted
        level: informational
        logsource: {product: linux, service: sshd}
        detection:
          selection: {action: ssh_accepted}
          condition: selection
    """,
    "correlations.yml": """
        title: SSH Brute Force
        id: ssh-bruteforce
        name: ssh_bruteforce
        level: medium
        correlation:
          type: event_count
          rules: [ssh_failed_password]
          group-by: [src_ip]
          timespan: 5m
          condition: {gte: 10}
        ---
        title: SSH Login After Brute Force
        id: ssh-success-after-bruteforce
        level: high
        correlation:
          type: temporal_ordered
          rules: [ssh_bruteforce, ssh_accepted]
          group-by: [src_ip]
          timespan: 5m
          generate: true
    """,
}


def test_chained_correlations_on_fixture(write_rules):
    ruleset = load_rules(write_rules(**SSH_RULES))
    assert ruleset.errors == []
    assert [c.meta.id for c in ruleset.correlations] == [
        "ssh-bruteforce",
        "ssh-success-after-bruteforce",
    ]
    events = collect(FIXTURES / "authlog" / "auth.log", year=2024).events
    alerts = Engine(ruleset).run(events)

    # The failed-password rule only feeds the brute force correlation. The
    # chained rule sets generate: true, which (as in the Sigma spec) applies to
    # all its inputs: the brute force alert and the accepted logins stay visible.
    assert [(alert.rule.id, len(alert.events)) for alert in alerts] == [
        ("ssh-success-after-bruteforce", 11),
        ("ssh-bruteforce", 10),
        ("ssh-accepted", 1),
        ("ssh-accepted", 1),
        ("ssh-accepted", 1),
    ]
    chained, bruteforce = alerts[:2]
    assert dict(chained.group) == {"src_ip": "203.0.113.45"}
    assert chained.events[-1].get("action") == "ssh_accepted"
    assert chained.events[-1].origin == "auth.log:18"
    assert bruteforce.rule.kind == "correlation"


def test_evaluation_keeps_hidden_results(write_rules):
    ruleset = load_rules(write_rules(**SSH_RULES))
    events = collect(FIXTURES / "authlog" / "auth.log", year=2024).events
    evaluation = Engine(ruleset).evaluate(events)
    # The failed passwords are hidden from the alerts but still recorded.
    assert len(evaluation.matches["ssh-failed"]) == 13
    assert "ssh-failed" not in {alert.rule.id for alert in evaluation.alerts}
    assert len(evaluation.correlation_alerts["ssh-bruteforce"]) == 1
    assert evaluation.alerts == Engine(ruleset).run(events)


def test_hidden_rules(write_rules):
    ruleset = load_rules(write_rules(**SSH_RULES))
    # Only the rule referenced by a non-generating correlation is hidden.
    assert ruleset.hidden_rule_ids() == {"ssh-failed"}
    assert ruleset.references["ssh_bruteforce"] == "ssh-bruteforce"
    assert ruleset.references["ssh-failed"] == "ssh-failed"


def test_broken_references_are_errors(write_rules):
    ruleset = load_rules(
        write_rules(
            **{
                "base.yml": SSH_RULES["ssh_failed.yml"],
                "broken.yml": """
                    title: Unknown Input
                    name: unknown_input
                    level: low
                    correlation:
                      type: event_count
                      rules: [nope]
                      timespan: 1m
                      condition: {gte: 2}
                    ---
                    title: Depends On Broken
                    level: low
                    correlation:
                      type: temporal
                      rules: [unknown_input, ssh_failed_password]
                      timespan: 1m
                    ---
                    title: Cycle A
                    name: cycle_a
                    level: low
                    correlation:
                      type: temporal
                      rules: [cycle_b, ssh_failed_password]
                      timespan: 1m
                    ---
                    title: Cycle B
                    name: cycle_b
                    level: low
                    correlation:
                      type: temporal
                      rules: [cycle_a, ssh_failed_password]
                      timespan: 1m
                    ---
                    title: Fine
                    level: low
                    correlation:
                      type: event_count
                      rules: [ssh_failed_password]
                      timespan: 1m
                      condition: {gte: 2}
                """,
            }
        )
    )
    assert [c.meta.title for c in ruleset.correlations] == ["Fine"]
    errors = [error.split("]", 1)[1] for error in ruleset.errors]
    assert errors == [
        ": unknown rule reference(s) nope",
        ": unknown rule reference(s) unknown_input",
        ": circular reference between correlations",
        ": circular reference between correlations",
    ]
    assert "unknown_input" not in ruleset.references
    assert "cycle_a" not in ruleset.references


def test_duplicate_name_is_rejected(write_rules):
    duplicate = SSH_RULES["ssh_accepted.yml"].replace(
        "name: ssh_accepted", "name: ssh_failed_password"
    )
    ruleset = load_rules(write_rules(**{"a.yml": SSH_RULES["ssh_failed.yml"], "b.yml": duplicate}))
    assert len(ruleset.detections) == 1
    assert ruleset.errors[0].endswith("duplicate rule id or name ssh_failed_password")
