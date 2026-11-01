"""One analysis run: read the logs, load the rules, run the engine."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import tzinfo
from pathlib import Path

from vigie.collect import Collection, Progress, collect
from vigie.models import Event
from vigie.rules import RULES_DIR
from vigie.sigma.engine import Engine, Evaluation
from vigie.sigma.loader import RuleSet, load_rules
from vigie.timeutils import UTC


@dataclass
class Analysis:
    """Everything an analysis produced, before any presentation choice."""

    collection: Collection
    ruleset: RuleSet
    evaluation: Evaluation


def analyze(
    logs: str | Path,
    *,
    rules: RuleSet | Iterable[str | Path] | None = None,
    year: int | None = None,
    tz: tzinfo = UTC,
    progress: Progress | None = None,
) -> Analysis:
    """Analyze a log folder (or one file) with the given rules, by default Vigie's own.

    ``rules`` is a loaded rule set, or rule files and folders to load. ``progress``, when
    given, is called as the analysis goes: ``"file"`` and ``"parsed"`` while files are read
    (see :func:`vigie.collect.collect`), ``"match"`` every few hundred events the rules have
    gone through, and ``"done"`` at the end. It only reports; results are the same without it.
    """
    collection = collect(logs, year=year, tz=tz, progress=progress)
    if isinstance(rules, RuleSet):
        ruleset = rules
    else:
        ruleset = load_rules(list(rules) if rules is not None else RULES_DIR)
    events: Iterable[Event] = collection.events
    if progress:
        events = _counted(collection.events, progress)
    evaluation = Engine(ruleset).evaluate(events)
    if progress:
        progress("done", events=len(collection.events), alerts=len(evaluation.alerts))
    return Analysis(collection, ruleset, evaluation)


def _counted(events: list[Event], progress: Progress, every: int = 250) -> Iterator[Event]:
    total = len(events)
    for done, event in enumerate(events):
        if done % every == 0:
            progress("match", done=done, total=total)
        yield event
    progress("match", done=total, total=total)
