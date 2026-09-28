"""Command line interface: ``vigie analyze`` and ``vigie rules``."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from datetime import datetime, tzinfo
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from vigie import __version__
from vigie.analysis import analyze
from vigie.attack import default_attack_data
from vigie.models import LEVELS
from vigie.report.builder import build_report
from vigie.report.render import render_html, render_json, render_markdown
from vigie.rules import RULES_DIR
from vigie.sigma.loader import RuleSet, load_rules
from vigie.timeutils import UTC

RENDERERS = {"html": render_html, "md": render_markdown, "json": render_json}
EXIT_USAGE = 2
DEFAULT_TIMELINE_LIMIT = 5000
MIN_YEAR, MAX_YEAR = 1, 9999  # the range of datetime


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except UsageError as exc:
        print(f"vigie: error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except BrokenPipeError:
        # Output piped into a command that stopped reading, such as head: stop quietly.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 1


class UsageError(Exception):
    """A problem with the command line the user can fix."""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vigie",
        description="Analyze Windows and Linux logs with Sigma rules mapped to MITRE ATT&CK.",
    )
    parser.add_argument("--version", action="version", version=f"vigie {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    run = commands.add_parser(
        "analyze",
        help="analyze a folder of logs and write a report",
        description="Read every supported log under LOGS (EVTX, OTRF JSON, auth.log), run the "
        "detection rules and write the report.",
    )
    run.add_argument("logs", type=Path, help="folder of logs (searched recursively) or one file")
    run.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("vigie-report"),
        help="folder for the report files (default: ./vigie-report)",
    )
    run.add_argument(
        "--format",
        default="html,md",
        help="comma-separated list of html, md and json (default: html,md)",
    )
    run.add_argument(
        "--min-level",
        choices=LEVELS,
        default="low",
        help="lowest severity shown in the report (default: low)",
    )
    run.add_argument(
        "--full-timeline",
        action="store_true",
        help="list every event in the timeline, not only those behind the alerts",
    )
    run.add_argument(
        "--timeline-limit",
        type=int,
        default=DEFAULT_TIMELINE_LIMIT,
        metavar="N",
        help=f"most events listed in the timeline (default: {DEFAULT_TIMELINE_LIMIT}); "
        "the report says how many were left out",
    )
    _rules_argument(run)
    run.add_argument(
        "--year",
        type=int,
        help="year of the first line of classic syslog files, which carry no year "
        "(default: guessed from the file's modification date)",
    )
    run.add_argument(
        "--tz",
        default="UTC",
        help="time zone of classic syslog lines, e.g. Europe/Berlin (default: UTC)",
    )
    run.set_defaults(handler=_analyze)

    rules = commands.add_parser("rules", help="list the detection rules and their ATT&CK mapping")
    _rules_argument(rules)
    rules.set_defaults(handler=_list_rules)
    return parser


def _rules_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--rules",
        type=Path,
        action="append",
        metavar="PATH",
        help="Sigma rule file or folder, repeatable; replaces the rules shipped with Vigie",
    )


def _analyze(args: argparse.Namespace) -> int:
    formats = _formats(args.format)
    tz = _timezone(args.tz)
    if not args.logs.exists():
        raise UsageError(f"no such file or directory: {args.logs}")
    if args.output.exists() and not args.output.is_dir():
        raise UsageError(f"--output must be a folder, {args.output} is a file")
    if args.year is not None and not MIN_YEAR <= args.year <= MAX_YEAR:
        raise UsageError(f"--year expects a year from {MIN_YEAR} to {MAX_YEAR}, got {args.year}")
    if args.timeline_limit < 1:
        raise UsageError(f"--timeline-limit expects a positive number, got {args.timeline_limit}")
    ruleset = _load_ruleset(args.rules)

    analysis = analyze(args.logs, rules=ruleset, year=args.year, tz=tz)
    report = build_report(
        analysis,
        generated_at=datetime.now(UTC),
        min_level=args.min_level,
        full_timeline=args.full_timeline,
        timeline_limit=args.timeline_limit,
    )

    args.output.mkdir(parents=True, exist_ok=True)
    written = []
    for fmt in formats:
        path = args.output / f"report.{fmt}"
        # Lone surrogates (a non UTF-8 file name, "\ud800" in JSON logs) cannot be
        # encoded: write them as escapes rather than fail halfway through a file.
        path.write_text(RENDERERS[fmt](report), encoding="utf-8", errors="backslashreplace")
        written.append(path)

    if not report.files:
        print(f"warning: no supported log file found in {args.logs}", file=sys.stderr)
    warnings = sum(len(f.warnings) for f in report.files)
    print(
        f"Read {report.event_count} events from {len(report.files)} file(s)"
        + (f", {len(report.skipped)} skipped" if report.skipped else "")
        + (f", {warnings} parser warning(s) listed in the report" if warnings else "")
        + f". {report.rule_count} rules loaded."
    )
    counts = ", ".join(f"{count} {level}" for level, count in report.level_counts.items() if count)
    hidden = sum(report.hidden_by_level.values())
    print(
        f"Alerts: {counts or 'none'}"
        + (f" ({hidden} below {args.min_level} not shown)" if hidden else "")
        + "."
    )
    if report.timeline_omitted:
        print(
            f"Timeline: {report.timeline_omitted} event(s) beyond the first "
            f"{args.timeline_limit} left out (see --timeline-limit)."
        )
    print("Report: " + ", ".join(str(path) for path in written))
    return 0


def _list_rules(args: argparse.Namespace) -> int:
    ruleset = _load_ruleset(args.rules)
    attack = default_attack_data()
    rules = sorted(
        [*ruleset.detections, *ruleset.correlations],
        key=lambda rule: (-rule.meta.severity, rule.meta.title),
    )
    hidden = ruleset.hidden_rule_ids()
    for rule in rules:
        techniques = ", ".join(t.id for t in attack.map_tags(rule.meta.tags).techniques)
        note = " (feeds a correlation)" if rule.meta.id in hidden else ""
        print(f"{rule.meta.level:<13} {rule.meta.title}{note}  [{techniques}]")
    return 0


def _load_ruleset(paths: list[Path] | None) -> RuleSet:
    """Load the ``--rules`` paths, or the shipped rules; report rejected rules on stderr."""
    for path in paths or []:
        if not path.exists():
            raise UsageError(f"no such rule file or directory: {path}")
    ruleset = load_rules(paths if paths else RULES_DIR)
    for error in ruleset.errors:
        print(f"warning: rule rejected: {error}", file=sys.stderr)
    if not ruleset.detections and not ruleset.correlations:
        raise UsageError("no valid rule loaded from " + ", ".join(map(str, paths or [RULES_DIR])))
    return ruleset


def _formats(value: str) -> list[str]:
    formats = [item.strip().lower() for item in value.split(",") if item.strip()]
    unknown = [item for item in formats if item not in RENDERERS]
    if unknown or not formats:
        raise UsageError(f"--format expects html, md or json, got {value!r}")
    return list(dict.fromkeys(formats))


def _timezone(name: str) -> tzinfo:
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise UsageError(f"unknown time zone {name!r}") from exc


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
