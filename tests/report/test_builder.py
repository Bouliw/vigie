from datetime import datetime

import pytest

from vigie.models import Event
from vigie.report.builder import EVIDENCE_LIMIT, build_report, summarize
from vigie.timeutils import UTC

from .conftest import GENERATED_AT

MIXED = (
    "authlog/auth.log",
    "evtx/DE_1102_security_log_cleared.evtx",
    "evtx/sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx",
)


def titles(report):
    return [alert.rule.title for alert in report.alerts]


def test_summary(analysis_of):
    report = build_report(analysis_of(*MIXED), generated_at=GENERATED_AT)
    assert report.generated_at == GENERATED_AT
    assert report.event_count == 29 + 112 + 1
    assert report.first_event == datetime(2019, 3, 17, 19, 37, 11, 661930, tzinfo=UTC)
    assert [f.path for f in report.files] == [
        "authlog/auth.log",
        "evtx/DE_1102_security_log_cleared.evtx",
        "evtx/sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx",
    ]
    assert report.rule_count == 23
    assert report.rule_errors == []
    assert report.attack_version == "19.2"


def test_informational_alerts_are_hidden_by_default(analysis_of):
    report = build_report(analysis_of(*MIXED), generated_at=GENERATED_AT)
    assert "SSH Login Accepted" not in titles(report)
    assert report.hidden_by_level == {"informational": 3}
    assert report.level_counts == {"critical": 0, "high": 3, "medium": 3, "low": 1}
    assert report.alert_count == 7


def test_min_level(analysis_of):
    analysis = analysis_of(*MIXED)
    everything = build_report(analysis, generated_at=GENERATED_AT, min_level="informational")
    assert titles(everything).count("SSH Login Accepted") == 3
    assert everything.hidden_by_level == {}
    high = build_report(analysis, generated_at=GENERATED_AT, min_level="high")
    assert {a.rule.level for a in high.alerts} == {"high"}
    assert high.level_counts == {"critical": 0, "high": 3}
    assert high.hidden_by_level == {"informational": 3, "low": 1, "medium": 3}
    with pytest.raises(ValueError, match="unknown level"):
        build_report(analysis, generated_at=GENERATED_AT, min_level="severe")


def test_alerts_most_severe_first_with_attack_and_author(analysis_of):
    report = build_report(analysis_of(*MIXED), generated_at=GENERATED_AT)
    severities = [alert.rule.severity for alert in report.alerts]
    assert severities == sorted(severities, reverse=True)
    (lsass,) = [a for a in report.alerts if a.rule.title.startswith("LSASS")]
    assert [t.id for t in lsass.attack.techniques] == ["T1003.001"]
    assert lsass.rule.author.endswith("(SigmaHQ), adapted by Bouliw")
    assert lsass.rule.license == "DRL-1.1"
    assert lsass.hosts == ("PC04.example.corp",)


def test_rule_summaries(analysis_of):
    report = build_report(analysis_of(*MIXED), generated_at=GENERATED_AT)
    assert [(s.rule.title, s.alert_count) for s in report.rules][:2] == [
        ("LSASS Memory Access With Credential Dumping Rights", 1),
        ("SSH Login After Brute Force", 1),
    ]
    assert sum(s.alert_count for s in report.rules) == report.alert_count


def test_tactics_in_matrix_order(analysis_of):
    report = build_report(analysis_of(*MIXED), generated_at=GENERATED_AT)
    names = [view.tactic.shortname for view in report.tactics]
    assert names == [
        "initial-access",
        "persistence",
        "privilege-escalation",
        "stealth",
        "defense-impairment",
        "credential-access",
    ]
    (credential,) = [v for v in report.tactics if v.tactic.shortname == "credential-access"]
    assert [t.id for t in credential.techniques] == ["T1003.001", "T1110.001", "T1110.003"]


def test_correlation_evidence_is_capped(analysis_of):
    report = build_report(analysis_of("authlog/auth.log"), generated_at=GENERATED_AT)
    (chain,) = [a for a in report.alerts if a.rule.title == "SSH Login After Brute Force"]
    assert chain.event_count == 11
    assert len(chain.evidence) == EVIDENCE_LIMIT
    assert chain.group == {"src_ip": "203.0.113.45"}
    # The first failures, then the login that completes the chain.
    assert all("Failed password" in e.summary for e in chain.evidence[:-1])
    assert chain.evidence[-1].summary.startswith("Accepted password")
    assert chain.evidence[-1].timestamp == chain.last_seen


def test_timeline_holds_the_events_behind_shown_alerts(analysis_of):
    report = build_report(analysis_of(*MIXED), generated_at=GENERATED_AT)
    assert not report.full_timeline
    stamps = [entry.timestamp for entry in report.timeline]
    assert stamps == sorted(stamps)
    assert all(entry.alert_titles for entry in report.timeline)
    (cleared,) = [e for e in report.timeline if e.event_id == 1102]
    assert cleared.level == "high"
    assert cleared.alert_titles == ("Security Event Log Cleared",)


def test_full_timeline_and_limit(analysis_of):
    analysis = analysis_of(*MIXED)
    full = build_report(analysis, generated_at=GENERATED_AT, full_timeline=True)
    assert len(full.timeline) == full.event_count
    assert full.timeline_omitted == 0
    capped = build_report(
        analysis, generated_at=GENERATED_AT, full_timeline=True, timeline_limit=10
    )
    assert len(capped.timeline) == 10
    assert capped.timeline_omitted == full.event_count - 10


def test_empty_analysis(analysis_of):
    report = build_report(analysis_of(), generated_at=GENERATED_AT)
    assert report.event_count == 0
    assert report.first_event is None
    assert report.alerts == []
    assert report.tactics == []
    assert report.timeline == []


def event(source, raw="", **fields):
    return Event(timestamp=datetime(2024, 1, 1, tzinfo=UTC), source=source, fields=fields, raw=raw)


def test_summarize():
    assert (
        summarize(event("auth", message="Failed password for root")) == "Failed password for root"
    )
    windows = event("sysmon", Image="C:\\x.exe", CommandLine="x.exe\n  -a", Channel="Sysmon")
    assert summarize(windows) == "CommandLine=x.exe -a Image=C:\\x.exe"
    assert summarize(event("security", raw="{}")) == "{}"
    assert (
        summarize(event("security", Data=("a", "b"), TargetUserName="bob")) == "TargetUserName=bob"
    )
    long = summarize(event("auth", message="x" * 500))
    assert len(long) == 240
    assert long.endswith("\u2026")
