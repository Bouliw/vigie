"""Turn an analysis into a report model that the Markdown, HTML and JSON outputs share.

The model holds only what the reader needs, already sorted and filtered:

* a summary (events read, alerts per severity, time range);
* the ATT&CK tactics and techniques seen, in matrix order;
* the alerts, most severe first, each with its rule, ATT&CK mapping, author
  (the Detection Rule License requires crediting rule authors in alerts) and
  the events that triggered it;
* a timeline of the events behind the shown alerts, or of every event;
* what was read, skipped, or rejected (files, parser warnings, rule errors).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

from vigie import __version__
from vigie.analysis import Analysis
from vigie.attack import AttackData, AttackMapping, Tactic, Technique, default_attack_data
from vigie.collect import FileReport
from vigie.models import LEVELS, Alert, Event, RuleMeta

# Fields worth showing in a one-line event summary, in order of interest.
SUMMARY_FIELDS = (
    "CommandLine",
    "Image",
    "NewProcessName",
    "ParentImage",
    "SourceImage",
    "TargetImage",
    "GrantedAccess",
    "ServiceName",
    "ImagePath",
    "TaskName",
    "SubjectUserName",
    "TargetUserName",
    "IpAddress",
    "WorkstationName",
    "Status",
    "SubStatus",
)
SUMMARY_LENGTH = 240
EVIDENCE_LIMIT = 10


@dataclass(frozen=True)
class EventView:
    timestamp: datetime
    source: str
    event_id: int | None
    host: str | None
    origin: str
    summary: str
    alert_titles: tuple[str, ...] = ()
    level: str | None = None  # most severe alert this event belongs to


@dataclass(frozen=True)
class AlertView:
    rule: RuleMeta
    attack: AttackMapping
    first_seen: datetime
    last_seen: datetime
    hosts: tuple[str, ...]
    group: dict[str, str]
    event_count: int
    # At most EVIDENCE_LIMIT events: the first ones and always the last one, which
    # for an ordered correlation is the decisive step (the login after the failures).
    evidence: tuple[EventView, ...]


@dataclass(frozen=True)
class RuleSummary:
    rule: RuleMeta
    alert_count: int
    first_seen: datetime
    last_seen: datetime


@dataclass(frozen=True)
class TacticView:
    tactic: Tactic
    alert_count: int
    techniques: tuple[Technique, ...]


@dataclass
class Report:
    generated_at: datetime
    min_level: str
    vigie_version: str = __version__
    attack_version: str = ""
    attack_copyright: str = ""
    event_count: int = 0
    first_event: datetime | None = None
    last_event: datetime | None = None
    level_counts: dict[str, int] = field(default_factory=dict)  # shown alerts per level
    hidden_by_level: dict[str, int] = field(default_factory=dict)  # alerts below min_level
    tactics: list[TacticView] = field(default_factory=list)
    rules: list[RuleSummary] = field(default_factory=list)  # one line per rule that fired
    alerts: list[AlertView] = field(default_factory=list)
    timeline: list[EventView] = field(default_factory=list)
    full_timeline: bool = False
    timeline_omitted: int = 0
    files: list[FileReport] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    rule_count: int = 0
    rule_errors: list[str] = field(default_factory=list)

    @property
    def alert_count(self) -> int:
        return len(self.alerts)


def build_report(
    analysis: Analysis,
    *,
    generated_at: datetime,
    min_level: str = "low",
    full_timeline: bool = False,
    timeline_limit: int = 5000,
    attack: AttackData | None = None,
) -> Report:
    """Build the report model. Alerts below ``min_level`` are counted but not shown."""
    if min_level not in LEVELS:
        raise ValueError(f"unknown level {min_level!r}, expected one of {', '.join(LEVELS)}")
    attack = attack or default_attack_data()
    threshold = LEVELS.index(min_level)
    all_alerts = analysis.evaluation.alerts
    shown = [alert for alert in all_alerts if alert.rule.severity >= threshold]
    hidden = Counter(alert.rule.level for alert in all_alerts if alert.rule.severity < threshold)

    events = analysis.collection.events
    ruleset = analysis.ruleset
    report = Report(
        generated_at=generated_at,
        min_level=min_level,
        attack_version=attack.version,
        attack_copyright=attack.copyright,
        event_count=len(events),
        first_event=events[0].timestamp if events else None,
        last_event=events[-1].timestamp if events else None,
        level_counts={level: 0 for level in reversed(LEVELS[threshold:])},
        hidden_by_level={level: hidden[level] for level in LEVELS if hidden[level]},
        full_timeline=full_timeline,
        files=list(analysis.collection.files),
        skipped=list(analysis.collection.skipped),
        rule_count=len(ruleset.detections) + len(ruleset.correlations),
        rule_errors=list(ruleset.errors),
    )

    # Which shown alerts each event belongs to, for the timeline.
    links: dict[int, list[Alert]] = {}
    for alert in shown:
        report.level_counts[alert.rule.level] += 1
        for event in alert.events:
            links.setdefault(id(event), []).append(alert)

    mappings = {alert.rule.id: attack.map_tags(alert.rule.tags) for alert in shown}
    report.alerts = [_alert_view(alert, mappings[alert.rule.id], links) for alert in shown]
    report.tactics = _tactic_views(shown, mappings, attack)
    report.rules = _rule_summaries(shown)

    # The timeline shows the events behind the shown alerts, or every event on request.
    selected = events if full_timeline else [event for event in events if id(event) in links]
    report.timeline_omitted = max(0, len(selected) - timeline_limit)
    report.timeline = [_event_view(event, links) for event in selected[:timeline_limit]]
    return report


def summarize(event: Event) -> str:
    """One readable line for an event: the auth.log message, or the key Windows fields."""
    if event.source == "auth":
        text = str(event.get("message") or event.raw)
    else:
        parts = [
            f"{name}={_flat(event.get(name))}"
            for name in SUMMARY_FIELDS
            if event.get(name) not in (None, "")
        ]
        text = " ".join(parts) if parts else event.raw
    text = " ".join(text.split())  # one line, even for multi-line command lines
    return text if len(text) <= SUMMARY_LENGTH else text[: SUMMARY_LENGTH - 1] + "…"


def _flat(value: object) -> str:
    return ", ".join(value) if isinstance(value, tuple) else str(value)


def _event_view(event: Event, links: dict[int, list[Alert]]) -> EventView:
    alerts = links.get(id(event), [])
    top = max(alerts, key=lambda alert: alert.rule.severity) if alerts else None
    return EventView(
        timestamp=event.timestamp,
        source=event.source,
        event_id=event.event_id,
        host=event.host,
        origin=event.origin,
        summary=summarize(event),
        alert_titles=tuple(dict.fromkeys(alert.rule.title for alert in alerts)),
        level=top.rule.level if top else None,
    )


def _alert_view(alert: Alert, mapping: AttackMapping, links: dict[int, list[Alert]]) -> AlertView:
    hosts = tuple(sorted({event.host for event in alert.events if event.host}))
    return AlertView(
        rule=alert.rule,
        attack=mapping,
        first_seen=alert.timestamp,
        last_seen=alert.last_seen,
        hosts=hosts,
        group=dict(alert.group),
        event_count=len(alert.events),
        evidence=tuple(_event_view(event, links) for event in _evidence(alert.events)),
    )


def _evidence(events: tuple[Event, ...]) -> tuple[Event, ...]:
    if len(events) <= EVIDENCE_LIMIT:
        return events
    return (*events[: EVIDENCE_LIMIT - 1], events[-1])


def _tactic_views(
    alerts: list[Alert], mappings: dict[str, AttackMapping], attack: AttackData
) -> list[TacticView]:
    counts: Counter[str] = Counter()
    techniques: dict[str, dict[str, Technique]] = {}
    for alert in alerts:
        mapping = mappings[alert.rule.id]
        for tactic in mapping.tactics:
            counts[tactic.shortname] += 1
            for technique in mapping.techniques:
                if tactic.shortname in technique.tactics:
                    techniques.setdefault(tactic.shortname, {})[technique.id] = technique
    return [
        TacticView(
            tactic=tactic,
            alert_count=counts[tactic.shortname],
            techniques=tuple(
                sorted(techniques.get(tactic.shortname, {}).values(), key=lambda t: t.id)
            ),
        )
        for tactic in attack.tactics
        if counts[tactic.shortname]
    ]


def _rule_summaries(alerts: list[Alert]) -> list[RuleSummary]:
    by_rule: dict[str, list[Alert]] = {}
    for alert in alerts:
        by_rule.setdefault(alert.rule.id, []).append(alert)
    summaries = [
        RuleSummary(
            rule=group[0].rule,
            alert_count=len(group),
            first_seen=min(alert.timestamp for alert in group),
            last_seen=max(alert.last_seen for alert in group),
        )
        for group in by_rule.values()
    ]
    return sorted(summaries, key=lambda s: (-s.rule.severity, -s.alert_count, s.rule.title))
