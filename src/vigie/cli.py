"""Command line interface: ``vigie analyze``, ``demo``, ``watch``, ``ui`` and ``rules``."""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import time
import webbrowser
from collections.abc import Sequence
from datetime import datetime, tzinfo
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from vigie import __version__
from vigie.analysis import analyze
from vigie.atlas import default_atlas_data
from vigie.attack import default_attack_data
from vigie.collect import detect_format
from vigie.demo import DEMO_LOGS, DEMO_YEAR
from vigie.models import LEVELS
from vigie.parsers import unifiedlog
from vigie.report.builder import Report, build_report
from vigie.report.render import render_html, render_json, render_markdown
from vigie.rules import RULES_DIR
from vigie.sigma.loader import RuleSet, load_rules
from vigie.term import TEXT, AnalysisProgress, Console, Spinner, TopAlert, show_summary
from vigie.timeutils import UTC
from vigie.watch import (
    FOLLOWED_FORMATS,
    LOG_COMMAND,
    FileSource,
    Source,
    UnifiedLogSource,
    Watcher,
    WatchError,
    notify,
)

RENDERERS = {"html": render_html, "md": render_markdown, "json": render_json}
EXIT_USAGE = 2
DEFAULT_TIMELINE_LIMIT = 5000
DEFAULT_REFRESH = 5
MIN_YEAR, MAX_YEAR = 1, 9999  # the range of datetime
SUPPORTED = (
    "Vigie reads Windows .evtx files, Windows events exported as JSON (.json, .jsonl, .zip), "
    "Linux auth.log or secure files, macOS unified log exports (.ndjson) and AI agent logs "
    "in JSON Lines"
)
EXAMPLES = """\
examples:
  vigie ui                            open the Vigie app in the browser
  vigie demo                          try Vigie on sample logs, opens the report
  vigie analyze ./logs --open         analyze a folder of logs and open the report
  vigie watch /var/log/auth.log       follow a log as it is written
  vigie rules                         list the detection rules
  vigie shortcut --remove             remove the desktop icon of the app
"""


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return EXIT_USAGE
    if args.command != "shortcut":
        _first_run()
    try:
        return args.handler(args)
    except UsageError as exc:
        _error(str(exc), exc.hint)
        return EXIT_USAGE
    except WatchError as exc:
        _error(str(exc), None)
        return 1
    except BrokenPipeError:
        # Output piped into a command that stopped reading, such as head: stop quietly.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 1


def _first_run() -> None:
    """The first time Vigie runs in a terminal, it adds its desktop icon (once)."""
    try:
        from vigie.shortcut import first_run

        first_run(sys.stderr)
    except Exception:  # an icon must never stop a command
        pass


class UsageError(Exception):
    """A problem with the command line the user can fix, and how to fix it."""

    def __init__(self, message: str, hint: str | None = None) -> None:
        super().__init__(message)
        self.hint = hint


def _error(message: str, hint: str | None) -> None:
    console = Console(sys.stderr, sys.stderr)  # colors only when stderr is a terminal
    print(f"vigie: {console.style('error', TEXT['high'])}: {message}", file=sys.stderr)
    if hint:
        print(f"{console.dim('hint')}: {hint}", file=sys.stderr)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vigie",
        description="Analyze Windows, Linux, macOS and AI agent logs with Sigma rules mapped to "
        "MITRE ATT&CK and ATLAS.",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"vigie {__version__}")
    commands = parser.add_subparsers(dest="command", metavar="COMMAND")

    run = commands.add_parser(
        "analyze",
        help="analyze a folder of logs and write a report",
        description="Read every supported log under LOGS (EVTX, OTRF JSON, auth.log, macOS "
        "unified log exports, AI agent logs), run the detection rules and write the report.",
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
    _min_level_argument(run)
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
    _tz_argument(run)
    run.add_argument(
        "--open", action="store_true", help="open the HTML report in the browser when done"
    )
    _plain_argument(run)
    run.set_defaults(handler=_analyze)

    demo = commands.add_parser(
        "demo",
        help="try Vigie on sample logs and open the report",
        description="Analyze the sample logs shipped with Vigie (synthetic AI agent logs and a "
        "Linux auth.log), write the HTML report and open it in the browser.",
    )
    demo.add_argument(
        "-o",
        "--output",
        type=Path,
        help="folder for report.html (default: a new temporary folder)",
    )
    demo.add_argument(
        "--no-open", action="store_true", help="write the report without opening the browser"
    )
    _plain_argument(demo)
    demo.set_defaults(handler=_demo)

    watch = commands.add_parser(
        "watch",
        help="follow logs as they are written and raise alerts as they happen",
        description="Follow log files (auth.log, unified log exports, AI agent logs) like "
        "tail -F and, with --macos, the unified log of this Mac. Every new event goes through "
        "the detection rules: alerts are printed, the most severe raise a macOS notification, "
        "and an HTML report reloads itself as they come in. Stop with Ctrl-C.",
    )
    watch.add_argument("files", type=Path, nargs="*", metavar="FILE", help="log file to follow")
    watch.add_argument(
        "--macos",
        action="store_true",
        help="follow the unified log of this Mac with `log stream` (no administrator rights)",
    )
    watch.add_argument(
        "--predicate",
        default=unifiedlog.PREDICATE,
        help="which unified log entries to read, as a `log stream` predicate "
        "(default: those Vigie's rules use)",
    )
    watch.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("vigie-report"),
        help="folder of the live report.html (default: ./vigie-report)",
    )
    _min_level_argument(watch, shown="printed and shown in the report")
    watch.add_argument(
        "--notify-level",
        choices=[*LEVELS, "off"],
        default="high",
        help="lowest severity that raises a macOS notification, or off (default: high)",
    )
    watch.add_argument(
        "--refresh",
        type=int,
        default=DEFAULT_REFRESH,
        metavar="SECONDS",
        help=f"how often the report reloads in the browser (default: {DEFAULT_REFRESH})",
    )
    _rules_argument(watch)
    _tz_argument(watch)
    _plain_argument(watch)
    watch.set_defaults(handler=_watch)

    app = commands.add_parser(
        "ui",
        help="open the Vigie app in the browser",
        description="Start the Vigie app on this computer (127.0.0.1 only) and open it in the "
        "browser: drop logs to analyze them, read the reports, watch logs live. It stops with "
        "Ctrl-C, or a few minutes after its last page is closed.",
    )
    app.add_argument("--port", type=int, help="port to listen on (default: a free one)")
    app.add_argument("--no-open", action="store_true", help="do not open the browser")
    app.set_defaults(handler=_ui)

    icon = commands.add_parser(
        "shortcut",
        help="add a desktop icon that opens the Vigie app, or remove it",
        description="Add an icon that opens the Vigie app (vigie ui) without a terminal: "
        "Vigie.app on macOS, a shortcut on the Windows Desktop, a desktop entry on Linux. "
        "Vigie adds it by itself the first time it runs in a terminal; --remove takes it "
        "away for good.",
    )
    icon.add_argument("--remove", action="store_true", help="remove the icon")
    icon.add_argument(
        "--applications",
        action="store_true",
        help="macOS: put Vigie.app in ~/Applications rather than on the Desktop",
    )
    icon.set_defaults(handler=_shortcut)

    rules = commands.add_parser(
        "rules", help="list the detection rules and their ATT&CK or ATLAS mapping"
    )
    _rules_argument(rules)
    rules.set_defaults(handler=_list_rules)
    return parser


def _min_level_argument(
    parser: argparse.ArgumentParser, shown: str = "shown in the report"
) -> None:
    parser.add_argument(
        "--min-level",
        choices=LEVELS,
        default="low",
        help=f"lowest severity {shown} (default: low)",
    )


def _tz_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--tz",
        default="UTC",
        help="time zone of classic syslog lines, e.g. Europe/Berlin (default: UTC)",
    )


def _rules_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--rules",
        type=Path,
        action="append",
        metavar="PATH",
        help="Sigma rule file or folder, repeatable; replaces the rules shipped with Vigie",
    )


def _plain_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--plain",
        action="store_true",
        help="plain text output, without colors or animation (as when piped; NO_COLOR too)",
    )


def _analyze(args: argparse.Namespace) -> int:
    console = Console(plain=args.plain)
    formats = _formats(args.format)
    tz = _timezone(args.tz)
    if not args.logs.exists():
        raise UsageError(
            f"no such file or directory: {args.logs}",
            "check the path; to see Vigie at work on sample logs first, run: vigie demo",
        )
    _check_output(args.output)
    if args.year is not None and not MIN_YEAR <= args.year <= MAX_YEAR:
        raise UsageError(f"--year expects a year from {MIN_YEAR} to {MAX_YEAR}, got {args.year}")
    if args.timeline_limit < 1:
        raise UsageError(f"--timeline-limit expects a positive number, got {args.timeline_limit}")
    if args.open and "html" not in formats:
        raise UsageError("--open opens the HTML report", "add html to --format, e.g. html,json")
    ruleset = _load_ruleset(args.rules, console)

    _header(console, f"analyzing {args.logs}")
    report, elapsed = _run(
        console,
        args.logs,
        ruleset,
        year=args.year,
        tz=tz,
        min_level=args.min_level,
        full_timeline=args.full_timeline,
        timeline_limit=args.timeline_limit,
    )
    written = _write(report, args.output, formats)
    _summary(
        console,
        report,
        written,
        source=args.logs,
        min_level=args.min_level,
        timeline_limit=args.timeline_limit,
        elapsed=elapsed,
        browse=args.output / "report.html" if args.open else None,
        tip="add --open to open the report in your browser when the analysis is done"
        if "html" in formats
        else None,
    )
    return 0


def _demo(args: argparse.Namespace) -> int:
    console = Console(plain=args.plain)
    # resolve(): on Windows, %TEMP% can hold a short 8.3 name (C:\Users\ABCDEF~1\...);
    # print the folder under its real name.
    output = args.output or Path(tempfile.mkdtemp(prefix="vigie-demo-")).resolve()
    _check_output(output)
    ruleset = _load_ruleset(None, console)
    intro = "the sample logs shipped with Vigie: synthetic AI agent logs and a Linux auth.log"
    if console.fancy:
        _header(console, f"demo on {intro}")
    else:
        print(f"Analyzing {intro}.")
    report, elapsed = _run(
        console,
        DEMO_LOGS,
        ruleset,
        year=DEMO_YEAR,
        tz=UTC,
        min_level="low",
        full_timeline=False,
        timeline_limit=DEFAULT_TIMELINE_LIMIT,
    )
    written = _write(report, output, ["html"])
    _summary(
        console,
        report,
        written,
        source=DEMO_LOGS,
        min_level="low",
        timeline_limit=DEFAULT_TIMELINE_LIMIT,
        elapsed=elapsed,
        browse=None if args.no_open else output / "report.html",
        tip=None,
    )
    return 0


def _check_output(output: Path) -> None:
    if output.exists() and not output.is_dir():
        raise UsageError(
            f"--output must be a folder, {output} is a file",
            "give a folder, new or existing, for example: -o ./vigie-report",
        )


def _header(console: Console, text: str) -> None:
    if console.fancy:
        console.print(f"{console.bold('Vigie')} {console.dim(__version__)}  {text}")


def _run(
    console: Console,
    logs: Path,
    ruleset: RuleSet,
    *,
    year: int | None,
    tz: tzinfo,
    min_level: str,
    full_timeline: bool,
    timeline_limit: int,
) -> tuple[Report, float]:
    """Analyze and build the report, with a progress line on a terminal."""
    started = time.monotonic()
    rule_count = len(ruleset.detections) + len(ruleset.correlations)
    progress = AnalysisProgress(console, rule_count)
    with Spinner(console, progress.line):
        analysis = analyze(
            logs, rules=ruleset, year=year, tz=tz, progress=progress if console.fancy else None
        )
    report = build_report(
        analysis,
        generated_at=datetime.now(UTC),
        min_level=min_level,
        full_timeline=full_timeline,
        timeline_limit=timeline_limit,
    )
    return report, time.monotonic() - started


def _write(report: Report, output: Path, formats: list[str]) -> list[Path]:
    output.mkdir(parents=True, exist_ok=True)
    written = []
    for fmt in formats:
        path = output / f"report.{fmt}"
        # Lone surrogates (a non UTF-8 file name, "\ud800" in JSON logs) cannot be
        # encoded: write them as escapes rather than fail halfway through a file.
        path.write_text(RENDERERS[fmt](report), encoding="utf-8", errors="backslashreplace")
        written.append(path)
    return written


def _summary(
    console: Console,
    report: Report,
    written: list[Path],
    *,
    source: Path,
    min_level: str,
    timeline_limit: int,
    elapsed: float,
    browse: Path | None,
    tip: str | None,
) -> None:
    """What was found and where the report is: plain lines, or a summary box on a terminal.

    The plain lines are what scripts may read: they do not change.
    """
    if not report.files:
        console.print(f"warning: no supported log file found in {source}", err=True)
        console.print(f"hint: {SUPPORTED}. To see Vigie at work, run: vigie demo", err=True)
    warnings = sum(len(f.warnings) for f in report.files)
    hidden = sum(report.hidden_by_level.values())
    if not console.fancy:
        print(
            f"Read {report.event_count} events from {len(report.files)} file(s)"
            + (f", {len(report.skipped)} skipped" if report.skipped else "")
            + (f", {warnings} parser warning(s) listed in the report" if warnings else "")
            + f". {report.rule_count} rules loaded."
        )
        counts = ", ".join(
            f"{count} {level}" for level, count in report.level_counts.items() if count
        )
        print(
            f"Alerts: {counts or 'none'}"
            + (f" ({hidden} below {min_level} not shown)" if hidden else "")
            + "."
        )
        if report.timeline_omitted:
            print(
                f"Timeline: {report.timeline_omitted} event(s) beyond the first "
                f"{timeline_limit} left out (see --timeline-limit)."
            )
        if browse is not None:
            _browse(console, browse)
        print("Report: " + ", ".join(str(path) for path in written))
        return

    notes = []
    if hidden:
        lower = next(iter(report.hidden_by_level))
        notes.append(f"{hidden} below {min_level} not shown (--min-level {lower} shows them)")
    if warnings:
        notes.append(f"{warnings} parser warning(s), listed in the report")
    if report.skipped:
        notes.append(f"{len(report.skipped)} file(s) skipped, listed in the report")
    if report.timeline_omitted:
        notes.append(f"timeline: {report.timeline_omitted} event(s) left out (--timeline-limit)")
    count = report.alert_count
    show_summary(
        console,
        headline=(count, "alert to review" if count == 1 else "alerts to review"),
        counts=report.level_counts,
        notes=notes,
        top=_top_alerts(report),
        footer=f"{report.event_count:,} events from {len(report.files)} file(s), "
        f"{report.rule_count} rules, {elapsed:.1f} s",
    )
    if browse is not None:
        _browse(console, browse)
    elif tip:
        console.print(console.dim(f"Tip: {tip}."))
    console.print(f"{console.bold('Report:')} " + ", ".join(str(path) for path in written))


def _top_alerts(report: Report, limit: int = 3) -> list[TopAlert]:
    frameworks = (default_attack_data(), default_atlas_data())
    return [
        TopAlert(
            level=summary.rule.level,
            title=summary.rule.title,
            count=summary.alert_count,
            techniques=tuple(
                technique.id
                for framework in frameworks
                for technique in framework.map_tags(summary.rule.tags).techniques
            ),
        )
        for summary in report.rules[:limit]
    ]


def _browse(console: Console, path: Path) -> None:
    try:
        opened = webbrowser.open(path.resolve().as_uri())
    except webbrowser.Error:
        opened = False
    if opened:
        console.print(
            console.dim("Opening the report in your browser.")
            if console.fancy
            else ("Opening the report in your browser.")
        )
    else:
        console.print(f"warning: could not open a browser; open {path} yourself", err=True)


def _watch(args: argparse.Namespace) -> int:
    console = Console(plain=args.plain)
    tz = _timezone(args.tz)
    if not args.files and not args.macos:
        raise UsageError(
            "nothing to watch: give log files to follow, or --macos",
            "for example: vigie watch /var/log/auth.log",
        )
    if args.macos and (sys.platform != "darwin" or not Path(LOG_COMMAND).exists()):
        raise UsageError("--macos reads the unified log of the Mac Vigie runs on: it needs macOS")
    if args.refresh < 1:
        raise UsageError(f"--refresh expects a positive number of seconds, got {args.refresh}")
    _check_output(args.output)
    formats = {path: _followed_format(path) for path in args.files}
    ruleset = _load_ruleset(args.rules, console)

    sources: list[Source] = [FileSource(path, fmt, tz=tz) for path, fmt in formats.items()]
    if args.macos:
        sources.append(UnifiedLogSource(args.predicate))
    notify_level = (
        None if args.notify_level == "off" or sys.platform != "darwin" else args.notify_level
    )
    report_path = args.output / "report.html"
    watcher = Watcher(
        sources,
        ruleset,
        report_path,
        min_level=args.min_level,
        notify_level=notify_level,
        refresh=args.refresh,
        notifier=notify,
        console=console,
    )
    names = [str(path) for path in args.files] + (["the macOS unified log"] if args.macos else [])
    rule_count = len(ruleset.detections) + len(ruleset.correlations)
    lines = [
        f"Watching {', '.join(names)} with {rule_count} rules. Stop with Ctrl-C.",
        f"Alerts at level {args.min_level} and above are printed"
        + (f"; {notify_level} and above also raise a notification." if notify_level else "."),
        f"Report: {report_path} (reloads every {args.refresh} s)",
    ]
    if console.fancy:
        _header(console, "watch")
        for line in lines:
            console.print(console.dim(line))
    else:
        for line in lines:
            print(line, flush=True)
    try:
        watcher.run()
    finally:
        console.clear_live()
        counts = {level: 0 for level in reversed(LEVELS)}
        for alert in watcher.alerts:
            counts[alert.rule.level] += 1
        summary = ", ".join(f"{count} {level}" for level, count in counts.items() if count)
        if console.fancy:
            shown = {
                level: count
                for level, count in counts.items()
                if LEVELS.index(level) >= LEVELS.index(args.min_level)
            }
            show_summary(
                console,
                headline=(sum(shown.values()), f"alerts at level {args.min_level} and above"),
                counts=shown,
                notes=[],
                top=[],
                footer=f"Stopped. Read {watcher.event_count:,} events from {len(sources)} "
                f"source(s).",
                animate=False,
            )
            console.print(f"{console.bold('Report:')} {report_path}")
        else:
            print(
                f"\nStopped. Read {watcher.event_count} events, alerts: {summary or 'none'}. "
                f"Report: {report_path}"
            )
    return 0


def _ui(args: argparse.Namespace) -> int:
    from vigie.ui.server import serve  # the app's modules load only when asked for

    if args.port is not None and not 0 < args.port < 65536:
        raise UsageError(f"--port expects a port number from 1 to 65535, got {args.port}")
    try:
        return serve(port=args.port, open_browser=not args.no_open)
    except OSError as exc:
        raise UsageError(
            f"cannot listen on port {args.port}: {exc.strerror or exc}",
            "pick another port, or leave --port out to use a free one",
        ) from exc


def _shortcut(args: argparse.Namespace) -> int:
    from vigie import shortcut

    if args.remove:
        removed = shortcut.remove()
        for path in removed:
            print(f"Removed {path}")
        if not removed:
            print("No Vigie icon to remove.")
        return 0
    try:
        made = shortcut.create(applications=args.applications)
    except (shortcut.ShortcutError, OSError) as exc:
        raise UsageError(f"could not add the icon: {exc}") from exc
    for path in made:
        print(f"Created {path}")
    print("Double-click it to open the Vigie app. Remove it with: vigie shortcut --remove")
    return 0


def _followed_format(path: Path) -> str:
    if not path.is_file():
        raise UsageError(f"no such file: {path}", "check the path of the log file to follow")
    fmt = detect_format(path)
    if path.suffix == ".gz" or fmt not in FOLLOWED_FORMATS:
        raise UsageError(
            f"{path}: vigie watch follows auth.log files, unified log exports (ndjson) and "
            "AI agent logs (JSON Lines); analyze other logs with vigie analyze",
            f"run: vigie analyze {path}",
        )
    return fmt


def _list_rules(args: argparse.Namespace) -> int:
    ruleset = _load_ruleset(args.rules)
    frameworks = (default_attack_data(), default_atlas_data())
    rules = sorted(
        [*ruleset.detections, *ruleset.correlations],
        key=lambda rule: (-rule.meta.severity, rule.meta.title),
    )
    hidden = ruleset.hidden_rule_ids()
    for rule in rules:
        techniques = ", ".join(
            technique.id
            for framework in frameworks
            for technique in framework.map_tags(rule.meta.tags).techniques
        )
        note = " (feeds a correlation)" if rule.meta.id in hidden else ""
        print(f"{rule.meta.level:<13} {rule.meta.title}{note}  [{techniques}]")
    return 0


def _load_ruleset(paths: list[Path] | None, console: Console | None = None) -> RuleSet:
    """Load the ``--rules`` paths, or the shipped rules; report rejected rules on stderr."""
    for path in paths or []:
        if not path.exists():
            raise UsageError(f"no such rule file or directory: {path}")
    ruleset = load_rules(paths if paths else RULES_DIR)
    for error in ruleset.errors:
        message = f"warning: rule rejected: {error}"
        if console:
            console.print(message, err=True)
        else:
            print(message, file=sys.stderr)
    if not ruleset.detections and not ruleset.correlations:
        raise UsageError(
            "no valid rule loaded from " + ", ".join(map(str, paths or [RULES_DIR])),
            "the warnings above say why each rule was rejected",
        )
    return ruleset


def _formats(value: str) -> list[str]:
    formats = [item.strip().lower() for item in value.split(",") if item.strip()]
    unknown = [item for item in formats if item not in RENDERERS]
    if unknown or not formats:
        raise UsageError(
            f"--format expects html, md or json, got {value!r}", "for example: --format html,json"
        )
    return list(dict.fromkeys(formats))


def _timezone(name: str) -> tzinfo:
    # UTC, the default, needs no time zone database: Windows has none of its own
    # (the tzdata package provides it there for the other names).
    if name.upper() == "UTC":
        return UTC
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise UsageError(
            f"unknown time zone {name!r}",
            "use a name from the time zone database, such as UTC or Europe/Paris",
        ) from exc


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
