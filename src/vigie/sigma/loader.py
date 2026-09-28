"""Load Sigma rules from YAML files and compile them for the engine.

A rule that cannot be used (invalid YAML, missing field, unsupported modifier
or logsource, reference to an unknown rule...) is not fatal: it is left out of
the rule set and the reason is recorded in :attr:`RuleSet.errors`, so one bad
file does not stop an analysis, and the user still learns why a rule never
fires.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any

import yaml

from vigie.models import LEVELS, Event, RuleMeta
from vigie.sigma.condition import Node, parse_condition
from vigie.sigma.correlation import CorrelationRule, parse_correlation
from vigie.sigma.logsource import Target, resolve_logsource
from vigie.sigma.matcher import Selection, SigmaError, compile_selection

RULE_SUFFIXES = (".yml", ".yaml")


@dataclass(frozen=True)
class DetectionRule:
    """A compiled Sigma detection rule, matching one event at a time."""

    meta: RuleMeta
    targets: tuple[Target, ...]
    selections: Mapping[str, Selection]
    condition: Node

    @property
    def sources(self) -> frozenset[str]:
        return frozenset(target.source for target in self.targets)

    def matches(self, event: Event) -> bool:
        target = next((t for t in self.targets if t.accepts(event)), None)
        if target is None:
            return False
        results: dict[str, bool] = {}

        def lookup(sigma_field: str) -> Any:
            return event.get(target.field_name(sigma_field))

        def resolve(name: str) -> bool:
            # Each selection is evaluated at most once per event.
            if name not in results:
                results[name] = self.selections[name].matches(lookup, event.raw)
            return results[name]

        return self.condition.evaluate(resolve)


@dataclass
class RuleSet:
    """Rules ready for the engine, plus the reasons some rules were rejected.

    ``correlations`` are in evaluation order: a correlation always comes after
    the correlations it references. ``references`` maps every rule ``name``
    and ``id`` to the rule id.
    """

    detections: list[DetectionRule] = field(default_factory=list)
    correlations: list[CorrelationRule] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    references: dict[str, str] = field(default_factory=dict)

    def hidden_rule_ids(self) -> set[str]:
        """Rules whose own alerts are replaced by the correlations using them.

        As in the Sigma specification, a rule referenced by a correlation only
        feeds that correlation, unless one referencing correlation sets
        ``generate: true``.
        """
        feeding, generating = set(), set()
        for correlation in self.correlations:
            ids = {self.references[ref] for ref in correlation.rules}
            (generating if correlation.generate else feeding).update(ids)
        return feeding - generating


def load_rules(paths: str | Path | Iterable[str | Path]) -> RuleSet:
    """Load every ``.yml``/``.yaml`` file under ``paths`` (files or folders, recursively)."""
    if isinstance(paths, (str, Path)):
        paths = [paths]
    ruleset = RuleSet()
    labels: dict[str, str] = {}
    correlations: list[CorrelationRule] = []
    for path in _rule_files([Path(p) for p in paths]):
        try:
            documents = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
        except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
            ruleset.errors.append(f"{path}: cannot read rule file ({_first_line(exc)})")
            continue
        for index, document in enumerate(documents, start=1):
            if document is None:
                continue
            label = _label(path, document, index, len(documents))
            try:
                rule = parse_rule(document, str(path))
            except SigmaError as exc:
                ruleset.errors.append(f"{label}: {exc}")
                continue
            meta = rule.meta
            if meta.id in ruleset.references:
                ruleset.errors.append(f"{label}: duplicate rule id or name {meta.id}")
                continue
            if meta.name and meta.name in ruleset.references:
                ruleset.errors.append(f"{label}: duplicate rule id or name {meta.name}")
                continue
            ruleset.references[meta.id] = meta.id
            if meta.name:
                ruleset.references[meta.name] = meta.id
            labels[meta.id] = label
            if isinstance(rule, CorrelationRule):
                correlations.append(rule)
            else:
                ruleset.detections.append(rule)
    _link_correlations(ruleset, correlations, labels)
    return ruleset


def parse_rule(document: Any, path: str = "") -> DetectionRule | CorrelationRule:
    """Validate and compile one Sigma rule given as a parsed YAML document."""
    if not isinstance(document, Mapping):
        raise SigmaError("a rule must be a YAML mapping")
    if "action" in document:
        raise SigmaError("Sigma v1 rule collections ('action: global') are not supported")
    if "correlation" in document:
        return parse_correlation(document, parse_meta(document, path, kind="correlation"))
    meta = parse_meta(document, path, kind="detection")

    targets = resolve_logsource(document.get("logsource"))
    detection = document.get("detection")
    if not isinstance(detection, Mapping) or "condition" not in detection:
        raise SigmaError("detection must be a mapping with a condition")
    if "timeframe" in detection:
        raise SigmaError("'timeframe' is not supported, use a correlation rule instead")
    selections = {
        str(name): compile_selection(str(name), definition)
        for name, definition in detection.items()
        if name != "condition"
    }
    if not selections:
        raise SigmaError("detection defines no selection")
    condition = parse_condition(detection["condition"], selections)
    return DetectionRule(meta, targets, MappingProxyType(selections), condition)


def parse_meta(document: Mapping[str, Any], path: str, kind: str) -> RuleMeta:
    """Read and validate the descriptive fields shared by all rule kinds."""
    title = document.get("title")
    if not isinstance(title, str) or not title.strip():
        raise SigmaError("missing or empty title")
    level = str(document.get("level", "")).lower()
    if level not in LEVELS:
        raise SigmaError(f"level must be one of {', '.join(LEVELS)}")
    rule_id = document.get("id") or title.strip()
    name = document.get("name")
    return RuleMeta(
        id=str(rule_id),
        title=title.strip(),
        level=level,
        kind=kind,
        name=str(name) if name else None,
        description=str(document.get("description") or "").strip(),
        status=str(document.get("status") or ""),
        author=str(document.get("author") or ""),
        date=str(document.get("modified") or document.get("date") or ""),
        references=_strings(document, "references"),
        tags=tuple(tag.lower() for tag in _strings(document, "tags")),
        falsepositives=_strings(document, "falsepositives"),
        license=str(document.get("license") or ""),
        path=path,
    )


def _strings(document: Mapping[str, Any], key: str) -> tuple[str, ...]:
    value = document.get(key)
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list) and all(isinstance(item, (str, int, float)) for item in value):
        return tuple(str(item) for item in value)
    raise SigmaError(f"'{key}' must be a string or a list of strings")


def _link_correlations(
    ruleset: RuleSet, correlations: list[CorrelationRule], labels: dict[str, str]
) -> None:
    """Drop correlations with unknown references or cycles, and order the others."""
    detection_ids = {rule.meta.id for rule in ruleset.detections}
    pending = {rule.meta.id: rule for rule in correlations}

    def resolvable(ref: str) -> bool:
        target = ruleset.references.get(ref)
        return target in detection_ids or target in pending

    # Dropping one correlation can orphan another that references it: repeat.
    changed = True
    while changed:
        changed = False
        for rule_id, rule in list(pending.items()):
            missing = [ref for ref in rule.rules if not resolvable(ref)]
            if missing:
                ruleset.errors.append(
                    f"{labels[rule_id]}: unknown rule reference(s) {', '.join(missing)}"
                )
                del pending[rule_id]
                changed = True

    # Topological sort: emit a correlation once all its inputs are available.
    while pending:
        ready = [
            rule
            for rule in pending.values()
            if all(ruleset.references[ref] not in pending for ref in rule.rules)
        ]
        if not ready:
            for rule_id in pending:
                ruleset.errors.append(f"{labels[rule_id]}: circular reference between correlations")
            break
        for rule in ready:
            ruleset.correlations.append(rule)
            del pending[rule.meta.id]

    kept = detection_ids | {rule.meta.id for rule in ruleset.correlations}
    ruleset.references = {ref: rid for ref, rid in ruleset.references.items() if rid in kept}


def _rule_files(paths: list[Path]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            files.extend(sorted(p for p in path.rglob("*") if p.suffix in RULE_SUFFIXES))
        else:
            files.append(path)
    return files


def _label(path: Path, document: Any, index: int, count: int) -> str:
    title = document.get("title") if isinstance(document, Mapping) else None
    where = f"{path}" if count == 1 else f"{path} (document {index})"
    return f"{where} [{title}]" if title else where


def _first_line(exc: Exception) -> str:
    return str(exc).strip().splitlines()[0] if str(exc).strip() else type(exc).__name__
