"""Terminal output for people: colors, a live progress line, alert toasts and a summary box.

All of it is meant for someone looking at a terminal. It turns itself off, and
Vigie prints the plain text it always printed, when the output is not a
terminal (a pipe, a file, a test), when ``NO_COLOR`` is set, when ``TERM`` is
``dumb``, with ``--plain``, or on a Windows console where escape sequences
cannot be turned on.
"""

from __future__ import annotations

import os
import re
import shutil
import sys
import threading
import time
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, TextIO

ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
# Severity badges (background) and severity text, in the 16 basic colors every
# terminal has. Critical and high are bold.
BADGE = {
    "critical": "1;97;41",
    "high": "1;97;101",
    "medium": "30;43",
    "low": "97;44",
    "informational": "30;47",
}
TEXT = {"critical": "1;31", "high": "1;91", "medium": "33", "low": "94", "informational": "2"}
_ANSI = re.compile(r"\033\[[0-9;?]*[A-Za-z]")


@dataclass(frozen=True)
class Glyphs:
    top_left: str
    top_right: str
    bottom_left: str
    bottom_right: str
    horizontal: str
    vertical: str
    spinner: str
    dot: str


UNICODE = Glyphs("╭", "╮", "╰", "╯", "─", "│", "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏", "●")
ASCII = Glyphs("+", "+", "+", "+", "-", "|", "|/-\\", "*")


def fancy_output(
    stream: TextIO,
    *,
    plain: bool = False,
    environ: Mapping[str, str] | None = None,
    platform: str | None = None,
) -> bool:
    """Whether ``stream`` gets colors and animation, or the plain text of a pipe."""
    env = os.environ if environ is None else environ
    if plain or "NO_COLOR" in env or env.get("TERM") == "dumb":
        return False
    isatty = getattr(stream, "isatty", None)
    try:
        if not isatty or not isatty():
            return False
    except ValueError:  # a closed stream
        return False
    if (platform or sys.platform) == "win32":
        return enable_windows_vt(stream)
    return True


def enable_windows_vt(stream: TextIO) -> bool:
    """Turn on escape sequences in a Windows console (Windows Terminal, PowerShell, cmd).

    Returns False, for plain output, when anything fails: an old console, output
    redirected, or not Windows at all.
    """
    try:
        handle = _os_handle(stream)
        mode = _console_mode(handle)
        if mode is None:
            return False
        if mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING:
            return True
        return _set_console_mode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING)
    except Exception:  # any failure means plain output, never a crash
        return False


def _os_handle(stream: TextIO) -> int:
    import msvcrt  # Windows only

    return int(msvcrt.get_osfhandle(stream.fileno()))  # type: ignore[attr-defined]


def _console_mode(handle: int) -> int | None:
    import ctypes

    mode = ctypes.c_uint32()
    if not ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode)):  # type: ignore[attr-defined]
        return None
    return int(mode.value)


def _set_console_mode(handle: int, mode: int) -> bool:
    import ctypes

    return bool(ctypes.windll.kernel32.SetConsoleMode(handle, mode))  # type: ignore[attr-defined]


def can_encode(stream: TextIO, sample: str) -> bool:
    encoding = getattr(stream, "encoding", None) or "ascii"
    try:
        sample.encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def width_of(text: str) -> int:
    """Columns ``text`` takes on screen: escape sequences take none, wide characters two."""
    text = _ANSI.sub("", text)
    return sum(
        0
        if unicodedata.combining(char)
        else 2
        if unicodedata.east_asian_width(char) in ("W", "F")
        else 1
        for char in text
    )


def fit(text: str, width: int) -> str:
    """Plain ``text`` cut to ``width`` columns, with an ellipsis when it was cut."""
    text = " ".join(text.split())
    if width_of(text) <= width:
        return text
    out, used = [], 0
    for char in text:
        size = width_of(char)
        if used + size > width - 1:
            break
        out.append(char)
        used += size
    return "".join(out) + "…"


class Console:
    """Where Vigie writes for people: stdout, stderr and, on a terminal, one live line.

    The live line (a progress line, the status of a watch) stays at the bottom:
    anything printed meanwhile goes above it, warnings on stderr included.
    """

    def __init__(
        self,
        out: TextIO | None = None,
        err: TextIO | None = None,
        *,
        plain: bool = False,
        environ: Mapping[str, str] | None = None,
        platform: str | None = None,
    ) -> None:
        self.out = out if out is not None else sys.stdout
        self.err = err if err is not None else sys.stderr
        self.fancy = fancy_output(self.out, plain=plain, environ=environ, platform=platform)
        sample = "".join(vars(UNICODE).values()) + "…"
        self.glyphs = UNICODE if self.fancy and can_encode(self.out, sample) else ASCII
        self.ellipsis_ok = self.glyphs is UNICODE
        self._lock = threading.RLock()
        self._live: str | None = None

    @property
    def width(self) -> int:
        return max(40, min(shutil.get_terminal_size((100, 24)).columns, 160))

    def style(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.fancy and code else text

    def bold(self, text: str) -> str:
        return self.style(text, "1")

    def dim(self, text: str) -> str:
        return self.style(text, "2")

    def badge(self, level: str, label: str | None = None) -> str:
        text = f" {(label or level).upper()} "
        return self.style(text, BADGE.get(level, "7"))

    def fit(self, text: str, width: int) -> str:
        cut = fit(text, width)
        return cut if self.ellipsis_ok or not cut.endswith("…") else cut[:-1] + "."

    def print(self, text: str = "", *, err: bool = False) -> None:
        stream = self.err if err else self.out
        with self._lock:
            self._erase()
            print(text, file=stream, flush=True)
            self._paint()

    def write_lines(self, lines: Sequence[str]) -> None:
        with self._lock:
            self._erase()
            for line in lines:
                self.out.write(line + "\n")
            self.out.flush()
            self._paint()

    def live(self, text: str) -> None:
        """Show ``text`` (already cut to the width) on the bottom line, replacing the last one."""
        if not self.fancy:
            return
        with self._lock:
            self._erase()
            self._live = text
            self._paint()

    def clear_live(self) -> None:
        with self._lock:
            self._erase()
            self._live = None

    def _erase(self) -> None:
        if self._live is not None:
            self.out.write("\r\033[2K")
            self.out.flush()

    def _paint(self) -> None:
        if self._live is not None:
            self.out.write(self._live)
            self.out.flush()


class Spinner:
    """Redraw a live line about 12 times a second while a long step runs (terminal only)."""

    def __init__(self, console: Console, render: Callable[[str], str], interval: float = 0.08):
        self.console = console
        self.render = render
        self.interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def __enter__(self) -> Spinner:
        if self.console.fancy:
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join()
        self.console.clear_live()

    def _run(self) -> None:
        frames = self.console.glyphs.spinner
        n = 0
        while True:
            self.console.live(self.render(frames[n % len(frames)]))
            n += 1
            if self._stop.wait(self.interval):
                return


@dataclass
class AnalysisProgress:
    """What an analysis is doing, kept up to date by its progress callback."""

    console: Console
    rule_count: int
    stage: str = "start"
    path: str = ""
    index: int = 0
    total: int = 0
    events: int = 0
    done: int = 0
    to_match: int = 0
    started: float = field(default_factory=time.monotonic)

    def __call__(self, stage: str, **details: Any) -> None:
        self.stage = stage
        if stage == "file":
            self.path, self.index, self.total = details["path"], details["index"], details["total"]
        elif stage == "parsed":
            self.events = details["events"]
        elif stage == "match":
            self.done, self.to_match = details["done"], details["total"]

    def line(self, frame: str) -> str:
        c = self.console
        width = c.width - 1
        if self.stage in ("match", "done"):
            head = f"Running {self.rule_count} rules"
            tail = f"{self.done:,}/{self.to_match:,} events"
        elif self.stage in ("file", "parsed"):
            head = f"Reading {min(self.index + 1, self.total)}/{self.total}"
            tail = f"{self.events:,} events  {self.path}"
        else:
            head, tail = "Looking for logs", ""
        plain = f"{frame} {head}  {tail}"
        if width_of(plain) > width:
            tail = c.fit(tail, max(0, width - width_of(f"{frame} {head}  ")))
        return f"{c.style(frame, '36')} {c.bold(head)}  {c.dim(tail)}"


@dataclass(frozen=True)
class TopAlert:
    level: str
    title: str
    count: int
    techniques: tuple[str, ...]


def summary_box(
    console: Console,
    *,
    headline: tuple[int, str],
    counts: Mapping[str, int],
    notes: Sequence[str],
    top: Sequence[TopAlert],
    footer: str,
    progress: float = 1.0,
) -> list[str]:
    """The framed summary printed at the end of an analysis, ``progress`` of the way counted up."""
    c, g = console, console.glyphs
    width = min(c.width, 84)
    inner = width - 4

    def n(value: int) -> int:
        return round(value * progress)

    def row(text: str = "") -> str:
        pad = max(0, inner - width_of(text))
        return f"{c.dim(g.vertical)} {text}{' ' * pad} {c.dim(g.vertical)}"

    number, rest = headline
    head = f"{c.bold(f'{n(number):,}')} {rest}"
    badges = []
    for level, count in counts.items():
        value = f"{n(count):,}"
        badges.append(
            f"{c.badge(level)} {c.bold(value) if count else c.dim(value)}"
            if count
            else f"{c.dim(level.upper())} {c.dim(value)}"
        )
    lines = [row(), row(head), row()]
    line = ""
    for badge in badges:
        candidate = f"{line}   {badge}" if line else badge
        if width_of(candidate) > inner and line:
            lines.append(row(line))
            line = badge
        else:
            line = candidate
    lines.append(row(line))
    lines += [row(c.dim(c.fit(note, inner))) for note in notes]
    if top:
        lines += [row(), row(c.bold("Top alerts"))]
        title_width = max(12, min(44, inner - 30))
        for alert in top:
            badge = c.badge(alert.level, _short(alert.level))
            count = f"{alert.count}x"
            left = f"{badge} {c.fit(alert.title, title_width):<{title_width}} {count:>4}"
            room = inner - width_of(left) - 2
            techniques = c.fit(" ".join(alert.techniques), room) if room > 6 else ""
            lines.append(row(f"{left}  {c.style(techniques, '36')}"))
    lines += [row(), row(c.dim(c.fit(footer, inner))), row()]
    title = " Summary "
    top_rule = (
        c.dim(g.top_left + g.horizontal * 2)
        + c.bold(title)
        + c.dim(g.horizontal * (width - 4 - len(title)) + g.top_right)
    )
    bottom_rule = c.dim(g.bottom_left + g.horizontal * (width - 2) + g.bottom_right)
    return [top_rule, *lines, bottom_rule]


def show_summary(console: Console, animate: bool = True, **parts: Any) -> None:
    """Print the summary box; on a terminal its numbers count up for about 300 ms."""
    if not console.fancy or not animate:
        console.write_lines(summary_box(console, **parts))
        return
    frames = 12
    lines = summary_box(console, progress=0.0, **parts)
    console.write_lines(lines)
    for frame in range(1, frames + 1):
        time.sleep(0.025)
        eased = 1 - (1 - frame / frames) ** 3
        lines = summary_box(console, progress=eased, **parts)
        with console._lock:
            console.out.write(f"\033[{len(lines)}F")
            for line in lines:
                console.out.write("\033[2K" + line + "\n")
            console.out.flush()


def _short(level: str) -> str | None:
    """Badge label: ``INFO`` rather than ``INFORMATIONAL``."""
    return "info" if level == "informational" else None


def toast(
    console: Console, *, when: str, level: str, title: str, techniques: str, what: str
) -> str:
    """One alert of ``vigie watch`` as a colored line: badge, time, rule, techniques, details."""
    c = console
    badge = c.badge(level, _short(level))
    head = f"{badge} {c.dim(when)}  {c.bold(title)}"
    tech = f"  {c.style(techniques, '36')}" if techniques else ""
    room = c.width - 1 - width_of(head + tech) - 2
    detail = f"  {c.fit(what, room)}" if room > 10 else ""
    return head + tech + detail
