"""Run a rule set over events and produce alerts."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field

from vigie.models import Alert, Event
from vigie.sigma.correlation import Occurrence, correlate
from vigie.sigma.loader import DetectionRule, RuleSet


@dataclass
class Evaluation:
    """Everything one run produced, including what hidden rules matched.

    ``matches`` holds, per detection rule id, the events it matched, and
    ``correlation_alerts`` the alerts of every correlation, whether or not
    they are shown. ``alerts`` is what the analyst sees.
    """

    matches: dict[str, list[Event]] = field(default_factory=dict)
    correlation_alerts: dict[str, list[Alert]] = field(default_factory=dict)
    alerts: list[Alert] = field(default_factory=list)


class Engine:
    """Match every event against the rules that apply to its source."""

    def __init__(self, ruleset: RuleSet) -> None:
        self.ruleset = ruleset
        # Index rules by source so a Sysmon event is never tested against
        # auth.log rules, and vice versa.
        self._by_source: dict[str, list[DetectionRule]] = defaultdict(list)
        for rule in ruleset.detections:
            for source in sorted(rule.sources):
                self._by_source[source].append(rule)

    def run(self, events: Iterable[Event]) -> list[Alert]:
        """Return all alerts, most severe first, then in chronological order."""
        return self.evaluate(events).alerts

    def evaluate(self, events: Iterable[Event]) -> Evaluation:
        """Run every rule and keep the intermediate results."""
        matches: dict[str, list[Event]] = defaultdict(list)
        for event in events:
            for rule in self._by_source.get(event.source, ()):
                if rule.matches(event):
                    matches[rule.meta.id].append(event)

        # Correlations consume the matches of the rules they reference, and
        # their own alerts can feed later correlations.
        occurrences: dict[str, list[Occurrence]] = {
            rule_id: [Occurrence.from_event(event) for event in matched]
            for rule_id, matched in matches.items()
        }
        correlation_alerts: dict[str, list[Alert]] = {}
        references = self.ruleset.references
        for correlation in self.ruleset.correlations:
            inputs = {ref: occurrences.get(references[ref], []) for ref in correlation.rules}
            fired = correlate(correlation, inputs)
            correlation_alerts[correlation.meta.id] = fired
            occurrences[correlation.meta.id] = [Occurrence.from_alert(alert) for alert in fired]

        hidden = self.ruleset.hidden_rule_ids()
        alerts = [
            Alert(rule.meta, (event,))
            for rule in self.ruleset.detections
            if rule.meta.id not in hidden
            for event in matches.get(rule.meta.id, ())
        ]
        for rule_id, fired in correlation_alerts.items():
            if rule_id not in hidden:
                alerts.extend(fired)
        return Evaluation(dict(matches), correlation_alerts, sort_alerts(alerts))


def sort_alerts(alerts: list[Alert]) -> list[Alert]:
    return sorted(alerts, key=lambda a: (-a.rule.severity, a.timestamp, a.rule.title))
