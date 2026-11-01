"""``vigie watch``: follow logs as they are written and raise alerts as they happen.

Sources are log files followed like ``tail -F`` (auth.log, unified log
exports in ndjson, AI agent logs in JSON Lines) and the live macOS unified
log, read from ``log stream``.
Each new event goes through the rules of ``vigie analyze``, evaluated one
event at a time (:class:`vigie.sigma.engine.Stream`). Every alert is printed;
the most severe ones also raise a macOS notification; and an HTML report,
rewritten as alerts come in, reloads itself in the browser.
"""

from __future__ import annotations

import os
import queue
import subprocess
import sys
import tempfile
import threading
import time
from collections import deque
from collections.abc import Callable, Sequence
from datetime import datetime, tzinfo
from pathlib import Path
from typing import BinaryIO, Protocol, TextIO

from vigie.analysis import Analysis
from vigie.atlas import AtlasData, default_atlas_data
from vigie.attack import AttackData, default_attack_data
from vigie.collect import Collection, FileReport
from vigie.models import LEVELS, Alert, Event
from vigie.parsers import agentlog, authlog, unifiedlog
from vigie.report.builder import build_report, summarize
from vigie.report.render import render_html, timestamp
from vigie.sigma.engine import Evaluation, Stream, sort_alerts
from vigie.sigma.loader import RuleSet
from vigie.term import Console, toast
from vigie.timeutils import UTC

LOG_COMMAND = "/usr/bin/log"
OSASCRIPT = "/usr/bin/osascript"
FOLLOWED_FORMATS = ("authlog", "unifiedlog", "agentlog")
NOTIFY_COOLDOWN = 60.0  # seconds between two notifications of the same rule
ANSI_COLORS = {"critical": "1;31", "high": "31", "medium": "33", "low": "34", "informational": "2"}


class WatchError(Exception):
    """A source stopped working (``log stream`` exited, for example)."""


class Source(Protocol):
    report: FileReport

    def poll(self, now: datetime) -> list[Event]: ...

    def close(self) -> None: ...


def _open_shared(path: Path) -> BinaryIO:
    """Open ``path`` for reading without stopping others from renaming or deleting it.

    On Windows, a file opened the usual way cannot be renamed or deleted while it
    is open, so following a log would block its rotation. There it is opened with
    FILE_SHARE_DELETE, as ``tail -F`` relies on everywhere else.
    """
    if os.name != "nt":
        return path.open("rb")
    import ctypes
    import msvcrt
    from ctypes import wintypes

    create_file = ctypes.WinDLL("kernel32", use_last_error=True).CreateFileW
    create_file.restype = wintypes.HANDLE
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    generic_read, share_all, open_existing, normal = 0x80000000, 0x7, 3, 0x80
    handle = create_file(str(path), generic_read, share_all, None, open_existing, normal, None)
    if handle is None or handle == ctypes.c_void_p(-1).value:
        error = ctypes.get_last_error()
        raise OSError(None, ctypes.FormatError(error).strip(), str(path), error)
    return os.fdopen(msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY), "rb")


class FileSource:
    """A log file followed like ``tail -F``: new lines only, through rotation and truncation."""

    def __init__(self, path: Path, fmt: str, *, tz: tzinfo = UTC) -> None:
        if fmt not in FOLLOWED_FORMATS:
            raise ValueError(f"cannot follow {fmt} files")
        self.path = path
        self.format = fmt
        self.tz = tz
        self.report = FileReport(str(path), fmt, 0)
        # An agent log record can depend on earlier ones (the system prompt of its
        # session, the MCP call it answers): one reader for the life of the source.
        self._agent_reader = agentlog.Reader()
        self._open()
        # Start at the end, but count the lines so origins match the file's line numbers.
        self._lineno = sum(
            chunk.count(b"\n") for chunk in iter(lambda: self._handle.read(1 << 20), b"")
        )

    def poll(self, now: datetime) -> list[Event]:
        events = self._read(now)
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            return events  # rotated away, the new file does not exist yet
        if stat.st_ino != self._inode or stat.st_size < self._handle.tell():
            # A new file under the name (rotation) or the same one emptied (copytruncate).
            self._handle.close()
            self._open()
            self._lineno = 0
            events += self._read(now)
        return events

    def close(self) -> None:
        self._handle.close()

    def _open(self) -> None:
        self._handle = _open_shared(self.path)
        self._inode = os.fstat(self._handle.fileno()).st_ino
        self._partial = b""

    def _read(self, now: datetime) -> list[Event]:
        data = self._handle.read()
        if not data:
            return []
        lines = (self._partial + data).split(b"\n")
        self._partial = lines.pop()  # an unfinished line waits for the rest of it
        events: list[Event] = []
        for line in lines:
            self._lineno += 1
            events += self._parse(line.decode("utf-8", errors="replace"), now)
        self.report.events += len(events)
        return events

    def _parse(self, text: str, now: datetime) -> list[Event]:
        name = self.path.name
        if self.format == "authlog":
            result = authlog.parse_line(text, name=name, lineno=self._lineno, now=now, tz=self.tz)
            self.report.warnings += result.warnings
            return result.events
        origin = f"{name}:{self._lineno}"
        if self.format == "agentlog":
            return self._agent_reader.read_line(text, origin=origin, warnings=self.report.warnings)
        event = unifiedlog.parse_line(text, origin=origin, warnings=self.report.warnings)
        return [event] if event else []


class UnifiedLogSource:
    """The live macOS unified log, read from ``log stream --style ndjson``.

    ``log stream`` needs no administrator rights for the entries Vigie reads.
    """

    def __init__(self, predicate: str = unifiedlog.PREDICATE, command: Sequence[str] = ()) -> None:
        self.command = list(command) or [
            LOG_COMMAND,
            "stream",
            "--style",
            "ndjson",
            "--level",
            "info",  # Background Task Management and XProtect write at the info level
            "--predicate",
            predicate,
        ]
        self.report = FileReport("macOS unified log (log stream)", "unifiedlog", 0)
        # stderr goes to a file: a pipe nobody reads could fill up and block log stream.
        self._stderr = tempfile.TemporaryFile()  # noqa: SIM115 (closed by close())
        self._process = subprocess.Popen(
            self.command,
            stdout=subprocess.PIPE,
            stderr=self._stderr,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        self._lines: queue.SimpleQueue[str | None] = queue.SimpleQueue()
        threading.Thread(target=self._pump, daemon=True).start()
        self._count = 0

    def poll(self, now: datetime) -> list[Event]:
        events: list[Event] = []
        while True:
            try:
                line = self._lines.get_nowait()
            except queue.Empty:
                break
            if line is None:
                if events:
                    self._lines.put(None)  # return these events first, report the end next time
                    break
                self._process.wait()
                self._stderr.seek(0)
                error = self._stderr.read().decode("utf-8", errors="replace").strip()
                raise WatchError(
                    f"log stream stopped (exit code {self._process.returncode})"
                    + (f": {error}" if error else "")
                )
            self._count += 1
            origin = f"log stream:{self._count}"
            event = unifiedlog.parse_line(line, origin=origin, warnings=self.report.warnings)
            if event is not None:
                events.append(event)
        self.report.events += len(events)
        return events

    def close(self) -> None:
        if self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
        self._stderr.close()

    def _pump(self) -> None:
        assert self._process.stdout is not None
        for line in self._process.stdout:
            self._lines.put(line)
        self._lines.put(None)  # end of the stream


def notify(title: str, message: str) -> None:
    """Show a macOS notification. The texts reach AppleScript as arguments, never as code."""
    script = ["on run argv", "display notification (item 2 of argv) with title (item 1 of argv)"]
    command = [OSASCRIPT, *(arg for line in [*script, "end run"] for arg in ("-e", line))]
    subprocess.run([*command, title, message], check=False, capture_output=True, timeout=10)


class Watcher:
    """Evaluate what the sources produce, print and notify alerts, keep the report up to date."""

    def __init__(
        self,
        sources: Sequence[Source],
        ruleset: RuleSet,
        report_path: Path,
        *,
        min_level: str = "low",
        notify_level: str | None = "high",
        refresh: int = 5,
        out: TextIO | None = None,
        notifier: Callable[[str, str], None] = notify,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        attack: AttackData | None = None,
        atlas: AtlasData | None = None,
        console: Console | None = None,
    ) -> None:
        self.sources = list(sources)
        self.ruleset = ruleset
        self.report_path = report_path
        self.min_level = min_level
        self.notify_level = notify_level
        self.refresh = refresh
        self.console = console
        self.out = out or (console.out if console else sys.stdout)
        self.notifier = notifier
        self.clock = clock
        self.attack = attack or default_attack_data()
        self.atlas = atlas or default_atlas_data()
        self.stream = Stream(ruleset)
        self.started = clock()
        self.alerts: list[Alert] = []
        self.event_count = 0
        self.first_event: datetime | None = None
        self.last_event: datetime | None = None
        # On a terminal, a console shows alerts as colored toasts above a status line;
        # without one, alerts are plain lines (colored levels on a terminal, as before).
        self._fancy = bool(console and console.fancy)
        self._color = console is None and self.out.isatty() and "NO_COLOR" not in os.environ
        self._rate: deque[tuple[float, int]] = deque()  # (monotonic time, events read)
        self._beat = False
        self._notified: dict[str, float] = {}  # rule id -> monotonic time of its last notification
        self._last_write = float("-inf")
        self._events_changed = self._alerts_changed = False

    def run(self, interval: float = 1.0) -> None:
        """Follow the sources until Ctrl-C (or a source fails), then write the final report."""
        try:
            self.write_report(live=True)
            while True:
                self.step()
                self.update_report()
                time.sleep(interval)
        except KeyboardInterrupt:
            pass
        finally:
            for source in self.sources:
                source.close()
            self.write_report(live=False)

    def step(self) -> list[Alert]:
        """Read what the sources wrote since the last step; return the alerts it raised."""
        now = self.clock()
        events = sorted(
            (event for source in self.sources for event in source.poll(now)),
            key=lambda event: event.timestamp,
        )
        fired = [alert for event in events for alert in self.stream.push(event)]
        for event in events:
            self.event_count += 1
            if self.first_event is None or event.timestamp < self.first_event:
                self.first_event = event.timestamp
            if self.last_event is None or event.timestamp > self.last_event:
                self.last_event = event.timestamp
        for alert in fired:
            self.alerts.append(alert)
            if alert.rule.severity >= LEVELS.index(self.min_level):
                if self._fancy and self.console:
                    self.console.print(self.format_toast(alert))
                else:
                    print(self.format_alert(alert), file=self.out, flush=True)
            self._notify(alert)
        self._events_changed |= bool(events)
        self._alerts_changed |= bool(fired)
        if self._fancy:
            self._status(len(events))
        return fired

    def _status(self, new_events: int) -> None:
        """The bottom line of a watch on a terminal: sources, events per second, alerts."""
        assert self.console is not None
        c = self.console
        now = time.monotonic()
        self._rate.append((now, new_events))
        while self._rate and now - self._rate[0][0] > 10:
            self._rate.popleft()
        span = max(1.0, now - self._rate[0][0]) if len(self._rate) > 1 else 1.0
        rate = sum(count for _, count in self._rate) / span
        threshold = LEVELS.index(self.min_level)
        shown = [alert for alert in self.alerts if alert.rule.severity >= threshold]
        top = max((alert.rule.severity for alert in shown), default=None)
        worst = (
            f" ({sum(1 for a in shown if a.rule.severity == top)} {LEVELS[top]})"
            if top is not None
            else ""
        )
        self._beat = not self._beat
        dot = c.style(c.glyphs.dot, "92" if self._beat else "32")
        text = (
            f"watching {len(self.sources)} source{'s' if len(self.sources) != 1 else ''}  "
            f"{self.event_count:,} events  {rate:,.1f}/s  "
            f"{len(shown)} alert{'s' if len(shown) != 1 else ''}{worst}  Ctrl-C to stop"
        )
        c.live(f"{dot} {c.dim(c.fit(text, c.width - 3))}")

    def update_report(self) -> None:
        """Rewrite the report: within a second of a new alert, every ``refresh`` s otherwise."""
        elapsed = time.monotonic() - self._last_write
        if (self._alerts_changed and elapsed >= 1) or (
            self._events_changed and elapsed >= self.refresh
        ):
            self.write_report(live=True)

    def write_report(self, *, live: bool) -> None:
        # Only the events behind alerts are kept: memory grows with alerts, not with events.
        behind = {id(event): event for alert in self.alerts for event in alert.events}
        collection = Collection(
            events=sorted(behind.values(), key=lambda event: event.timestamp),
            files=[source.report for source in self.sources],
        )
        evaluation = Evaluation(alerts=sort_alerts(self.alerts))
        report = build_report(
            Analysis(collection, self.ruleset, evaluation),
            generated_at=self.clock(),
            min_level=self.min_level,
            attack=self.attack,
            atlas=self.atlas,
        )
        report.event_count = self.event_count
        report.first_event, report.last_event = self.first_event, self.last_event
        report.watch_started = self.started
        report.refresh = self.refresh if live else 0
        # Write next to the report and rename: a browser reloading never reads half a file.
        self.report_path.parent.mkdir(parents=True, exist_ok=True)
        partial = self.report_path.with_name(f".{self.report_path.name}.tmp")
        partial.write_text(render_html(report), encoding="utf-8", errors="backslashreplace")
        partial.replace(self.report_path)
        self._last_write = time.monotonic()
        self._events_changed = self._alerts_changed = False

    def format_toast(self, alert: Alert) -> str:
        """An alert as a colored terminal line: severity badge, time, rule, techniques."""
        assert self.console is not None
        return toast(
            self.console,
            when=timestamp(alert.last_seen),
            level=alert.rule.level,
            title=alert.rule.title,
            techniques=" ".join(self._technique_ids(alert)),
            what=describe(alert),
        )

    def _technique_ids(self, alert: Alert) -> list[str]:
        return [
            technique.id
            for framework in (self.attack, self.atlas)
            for technique in framework.map_tags(alert.rule.tags).techniques
        ]

    def format_alert(self, alert: Alert) -> str:
        """One terminal line: time, level, rule, ATT&CK and ATLAS techniques, what happened."""
        techniques = ", ".join(self._technique_ids(alert))
        level = f"{alert.rule.level.upper():<13}"
        if self._color:
            level = f"\033[{ANSI_COLORS[alert.rule.level]}m{level}\033[0m"
        return f"{timestamp(alert.last_seen)}  {level} {alert.rule.title}  [{techniques}]  " + (
            describe(alert)
        )

    def _notify(self, alert: Alert) -> None:
        if self.notify_level is None or alert.rule.severity < LEVELS.index(self.notify_level):
            return
        # A burst of alerts from one rule (an ongoing brute force) notifies once a minute.
        now = time.monotonic()
        if now - self._notified.get(alert.rule.id, float("-inf")) < NOTIFY_COOLDOWN:
            return
        self._notified[alert.rule.id] = now
        message = f"{alert.rule.title}: {describe(alert)}"
        self.notifier(f"Vigie: {alert.rule.level} alert", message[:200])


def describe(alert: Alert) -> str:
    """What an alert is about: the event it matched, or the group and size of a correlation."""
    if alert.rule.kind != "correlation":
        return summarize(alert.events[0])
    group = ", ".join(f"{key}={value}" for key, value in alert.group.items())
    return f"{group} ({len(alert.events)} events)" if group else f"{len(alert.events)} events"
