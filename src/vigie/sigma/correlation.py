"""Sigma correlation rules (Sigma v2): patterns across several events.

A correlation rule references other rules by ``name`` or ``id`` and fires
when their matches form a pattern within a ``timespan``, per ``group-by``
value (e.g. per source IP)::

    title: SSH brute force
    correlation:
      type: event_count
      rules: [ssh_failed_password]
      group-by: [src_ip]
      timespan: 5m
      condition: {gte: 10}
    level: high

Supported types:

* ``event_count``: at least N matching events in the window;
* ``value_count``: at least N distinct values of ``condition.field``
  (e.g. one IP trying many user names: password spraying);
* ``temporal``: every referenced rule matched in the window, in any order;
* ``temporal_ordered``: every referenced rule matched, in the listed order.

A correlation may reference another correlation ("a successful login right
after a brute force"): the referenced correlation's alerts are then its
input events, timestamped when the pattern completed.

When a pattern fires, its window is cleared, so a long brute force yields one
alert per burst of N attempts rather than one alert per attempt.
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from types import MappingProxyType
from typing import Any

from vigie.models import Alert, Event, RuleMeta
from vigie.sigma.matcher import SigmaError

TYPES = ("event_count", "value_count", "temporal", "temporal_ordered")
_TIMESPAN = re.compile(r"^(\d+)([smhdw])$")
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days", "w": "weeks"}


@dataclass(frozen=True)
class CorrelationRule:
    """A compiled Sigma correlation rule."""

    meta: RuleMeta
    type: str
    rules: tuple[str, ...]
    group_by: tuple[str, ...]
    timespan: timedelta
    threshold: int = 0  # minimum count, for event_count and value_count
    value_field: str | None = None  # counted field, for value_count
    aliases: Mapping[str, Mapping[str, str]] = field(default_factory=dict)
    generate: bool = False

    def field_for(self, name: str, ref: str) -> str:
        """Field holding group-by ``name`` in events of rule ``ref`` (after aliases)."""
        return self.aliases.get(name, {}).get(ref, name)


@dataclass(frozen=True)
class Occurrence:
    """One input of a correlation: an event matched by a rule, or an alert of a correlation."""

    timestamp: datetime
    events: tuple[Event, ...]
    values: Mapping[str, Any]

    @classmethod
    def from_event(cls, event: Event) -> Occurrence:
        return cls(event.timestamp, (event,), event.fields)

    @classmethod
    def from_alert(cls, alert: Alert) -> Occurrence:
        return cls(alert.last_seen, alert.events, alert.group)

    def value(self, name: str) -> str | None:
        value = self.values.get(name)
        # A multi-valued field cannot identify a single group.
        return value if isinstance(value, str) else None


def parse_correlation(document: Mapping[str, Any], meta: RuleMeta) -> CorrelationRule:
    """Validate and compile the ``correlation`` section of a rule."""
    section = document.get("correlation")
    if not isinstance(section, Mapping):
        raise SigmaError("correlation must be a mapping")

    kind = section.get("type")
    if kind not in TYPES:
        raise SigmaError(f"correlation type must be one of {', '.join(TYPES)}")
    rules = _string_list(section.get("rules"), "correlation rules")
    if not rules:
        raise SigmaError("correlation rules must not be empty")
    if kind.startswith("temporal") and len(rules) < 2:
        raise SigmaError(f"{kind} needs at least two rules")
    group_by = _string_list(section.get("group-by", []), "group-by")
    timespan = parse_timespan(section.get("timespan"))
    aliases = _aliases(section.get("aliases", {}), rules)
    generate = section.get("generate", False)
    if not isinstance(generate, bool):
        raise SigmaError("generate must be true or false")

    threshold, value_field = 0, None
    if kind in ("event_count", "value_count"):
        threshold, value_field = _condition(section.get("condition"), kind)
    elif section.get("condition") is not None:
        raise SigmaError(f"{kind} does not take a condition")

    return CorrelationRule(
        meta=meta,
        type=kind,
        rules=tuple(rules),
        group_by=tuple(group_by),
        timespan=timespan,
        threshold=threshold,
        value_field=value_field,
        aliases=aliases,
        generate=generate,
    )


def parse_timespan(value: Any) -> timedelta:
    """Parse a Sigma timespan such as ``30s``, ``5m``, ``1h``, ``2d``."""
    match = _TIMESPAN.match(str(value).strip()) if value is not None else None
    if not match or int(match[1]) == 0:
        raise SigmaError(f"invalid timespan {value!r}, expected e.g. 30s, 5m, 1h or 1d")
    return timedelta(**{_UNITS[match[2]]: int(match[1])})


def correlate(rule: CorrelationRule, inputs: Mapping[str, Sequence[Occurrence]]) -> list[Alert]:
    """Evaluate ``rule`` on the occurrences of each referenced rule (keyed by reference)."""
    # (timestamp, position of the rule in `rules`, occurrence), per group.
    groups: dict[tuple[str | None, ...], list[tuple[datetime, int, Occurrence]]]
    groups = defaultdict(list)
    for ref in dict.fromkeys(rule.rules):  # each distinct reference once, in order
        position = rule.rules.index(ref)
        for occurrence in inputs.get(ref, ()):
            key = tuple(occurrence.value(rule.field_for(name, ref)) for name in rule.group_by)
            if None in key:
                continue
            groups[key].append((occurrence.timestamp, position, occurrence))

    evaluate = {
        "event_count": _event_count,
        "value_count": _value_count,
        "temporal": _temporal,
        "temporal_ordered": _temporal_ordered,
    }[rule.type]

    alerts = []
    for key, items in groups.items():
        items.sort(key=lambda item: (item[0], item[1]))
        group = dict(zip(rule.group_by, key, strict=True))
        for window in evaluate(rule, [(position, occ) for _, position, occ in items]):
            alerts.append(Alert(rule.meta, _unique_events(window), group))
    return alerts


Tagged = tuple[int, Occurrence]


def _event_count(rule: CorrelationRule, items: list[Tagged]) -> list[list[Occurrence]]:
    fired, window = [], _Window(rule.timespan)
    for _position, occurrence in items:
        window.push(occurrence)
        if len(window) >= rule.threshold:
            fired.append(window.flush())
    return fired


def _value_count(rule: CorrelationRule, items: list[Tagged]) -> list[list[Occurrence]]:
    counted = rule.value_field or ""
    fired, window = [], _Window(rule.timespan)
    for position, occurrence in items:
        window.push(occurrence, occurrence.value(rule.field_for(counted, rule.rules[position])))
        if len({tag for tag in window.tags() if tag is not None}) >= rule.threshold:
            fired.append(window.flush())
    return fired


def _temporal(rule: CorrelationRule, items: list[Tagged]) -> list[list[Occurrence]]:
    fired, window = [], _Window(rule.timespan)
    for position, occurrence in items:
        window.push(occurrence, position)
        if len(set(window.tags())) == len(set(rule.rules)):
            fired.append(window.flush())
    return fired


def _temporal_ordered(rule: CorrelationRule, items: list[Tagged]) -> list[list[Occurrence]]:
    # chains[j]: the partial sequence matching rules[0..j] with the latest
    # start, which leaves the most time for the remaining steps.
    steps = len(rule.rules)
    chains: list[list[Occurrence] | None] = [None] * steps
    fired = []
    for position, occurrence in items:
        # A rule may appear at several positions; walk backwards so that one
        # occurrence never fills two consecutive steps.
        for step in reversed(range(steps)):
            if rule.rules[step] != rule.rules[position]:
                continue
            if step == 0:
                candidate = [occurrence]
            else:
                previous = chains[step - 1]
                if previous is None or occurrence.timestamp - previous[0].timestamp > rule.timespan:
                    continue
                candidate = [*previous, occurrence]
            current = chains[step]
            if current is None or candidate[0].timestamp >= current[0].timestamp:
                chains[step] = candidate
        complete = chains[-1]
        if complete is not None:
            fired.append(complete)
            chains = [None] * steps
    return fired


class _Window:
    """Occurrences within ``timespan`` of the newest one, each with an optional tag."""

    def __init__(self, timespan: timedelta) -> None:
        self.timespan = timespan
        self.items: deque[tuple[Occurrence, Any]] = deque()

    def push(self, occurrence: Occurrence, tag: Any = None) -> None:
        self.items.append((occurrence, tag))
        while occurrence.timestamp - self.items[0][0].timestamp > self.timespan:
            self.items.popleft()

    def __len__(self) -> int:
        return len(self.items)

    def tags(self) -> list[Any]:
        return [tag for _, tag in self.items]

    def flush(self) -> list[Occurrence]:
        occurrences = [occurrence for occurrence, _ in self.items]
        self.items.clear()
        return occurrences


def _unique_events(occurrences: list[Occurrence]) -> tuple[Event, ...]:
    seen: dict[int, Event] = {}
    for occurrence in occurrences:
        for event in occurrence.events:
            seen.setdefault(id(event), event)
    return tuple(seen.values())


def _string_list(value: Any, what: str) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return list(value)
    raise SigmaError(f"{what} must be a string or a list of strings")


def _aliases(value: Any, rules: list[str]) -> Mapping[str, Mapping[str, str]]:
    if not isinstance(value, Mapping):
        raise SigmaError("aliases must be a mapping")
    aliases: dict[str, Mapping[str, str]] = {}
    for alias, mapping in value.items():
        if not isinstance(mapping, Mapping) or not all(
            isinstance(v, str) for v in mapping.values()
        ):
            raise SigmaError(f"alias '{alias}' must map rule references to field names")
        unknown = [ref for ref in mapping if ref not in rules]
        if unknown:
            raise SigmaError(f"alias '{alias}' refers to rules not in the correlation: {unknown}")
        aliases[str(alias)] = MappingProxyType(dict(mapping))
    return MappingProxyType(aliases)


def _condition(value: Any, kind: str) -> tuple[int, str | None]:
    if not isinstance(value, Mapping):
        raise SigmaError(f"{kind} needs a condition such as {{gte: 10}}")
    operators = {key: value[key] for key in value if key != "field"}
    unsupported = [key for key in operators if key not in ("gt", "gte")]
    if unsupported or len(operators) != 1:
        raise SigmaError("only a single 'gt' or 'gte' threshold is supported in conditions")
    (operator, limit), *_ = operators.items()
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise SigmaError(f"condition {operator} must be a positive integer")
    threshold = limit + 1 if operator == "gt" else limit

    value_field = value.get("field")
    if kind == "value_count" and not isinstance(value_field, str):
        raise SigmaError("value_count needs condition.field, the field whose values are counted")
    if kind == "event_count" and value_field is not None:
        raise SigmaError("condition.field only applies to value_count")
    return threshold, value_field
