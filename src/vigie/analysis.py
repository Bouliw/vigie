"""One analysis run: read the logs, load the rules, run the engine."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import tzinfo
from pathlib import Path

from vigie.collect import Collection, collect
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
) -> Analysis:
    """Analyze a log folder (or one file) with the given rules, by default Vigie's own.

    ``rules`` is a loaded rule set, or rule files and folders to load.
    """
    collection = collect(logs, year=year, tz=tz)
    if isinstance(rules, RuleSet):
        ruleset = rules
    else:
        ruleset = load_rules(list(rules) if rules is not None else RULES_DIR)
    evaluation = Engine(ruleset).evaluate(collection.events)
    return Analysis(collection, ruleset, evaluation)
