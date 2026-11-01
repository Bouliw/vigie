"""Terminal output: when it is fancy, when it stays plain, and what it looks like."""

import io
import os
import re
import sys
import threading

import pytest

from vigie import term
from vigie.term import (
    ASCII,
    UNICODE,
    AnalysisProgress,
    Console,
    Spinner,
    TopAlert,
    enable_windows_vt,
    fancy_output,
    fit,
    show_summary,
    summary_box,
    toast,
    width_of,
)

ANSI = re.compile(r"\033\[")


class TTY(io.StringIO):
    """A stream that says it is a terminal."""

    encoding = "utf-8"

    def isatty(self):
        if self.closed:
            raise ValueError("I/O operation on closed file")
        return True


class AsciiTTY(TTY):
    encoding = "ascii"


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    monkeypatch.setattr(term.time, "sleep", lambda _seconds: None)


def test_plain_unless_a_terminal():
    assert fancy_output(TTY(), environ={}, platform="linux")
    assert not fancy_output(io.StringIO(), environ={}, platform="linux")
    assert not fancy_output(TTY(), plain=True, environ={}, platform="linux")


@pytest.mark.parametrize("environ", [{"NO_COLOR": "1"}, {"NO_COLOR": ""}, {"TERM": "dumb"}])
def test_no_color_and_dumb_terminals_get_plain_text(environ):
    assert not fancy_output(TTY(), environ=environ, platform="linux")
    console = Console(TTY(), TTY(), environ=environ, platform="linux")
    assert not console.fancy
    assert console.style("x", "1") == "x"
    console.live("progress")
    console.print("line")
    assert console.out.getvalue() == "line\n"


def test_closed_stream_is_plain():
    stream = TTY()
    stream.close()
    assert not fancy_output(stream, environ={}, platform="linux")


def test_windows_turns_on_escape_sequences(monkeypatch):
    calls = []
    monkeypatch.setattr(term, "_os_handle", lambda stream: 7)
    monkeypatch.setattr(term, "_console_mode", lambda handle: 0x0003)
    monkeypatch.setattr(
        term, "_set_console_mode", lambda handle, mode: calls.append((handle, mode)) or True
    )
    assert fancy_output(TTY(), environ={}, platform="win32")
    assert calls == [(7, 0x0003 | term.ENABLE_VIRTUAL_TERMINAL_PROCESSING)]


def test_windows_already_on(monkeypatch):
    monkeypatch.setattr(term, "_os_handle", lambda stream: 7)
    monkeypatch.setattr(term, "_console_mode", lambda handle: 0x0007)
    monkeypatch.setattr(term, "_set_console_mode", lambda handle, mode: pytest.fail("not needed"))
    assert enable_windows_vt(TTY())


@pytest.mark.parametrize(
    ("mode", "set_ok", "error"),
    [(None, True, None), (0x0003, False, None), (0x0003, True, OSError("no console"))],
)
def test_windows_falls_back_to_plain_text(monkeypatch, mode, set_ok, error):
    def handle(stream):
        if error:
            raise error
        return 7

    monkeypatch.setattr(term, "_os_handle", handle)
    monkeypatch.setattr(term, "_console_mode", lambda handle: mode)
    monkeypatch.setattr(term, "_set_console_mode", lambda handle, mode: set_ok)
    assert not fancy_output(TTY(), environ={}, platform="win32")
    console = Console(TTY(), TTY(), environ={}, platform="win32")
    assert not console.fancy and console.glyphs is ASCII


def test_real_windows_calls_fail_safely_elsewhere():
    if sys.platform != "win32":
        assert not enable_windows_vt(TTY())  # no msvcrt, no ctypes.windll: plain text


def test_glyphs_follow_the_encoding():
    assert Console(TTY(), environ={}, platform="linux").glyphs is UNICODE
    console = Console(AsciiTTY(), environ={}, platform="linux")
    assert console.fancy and console.glyphs is ASCII
    assert console.fit("a long title here", 8) == "a long ."


def test_width_and_fit():
    assert width_of("\033[1mabc\033[0m") == 3
    assert width_of("日本") == 4
    assert fit("abcdef", 4) == "abc…"
    assert fit("two\nlines", 20) == "two lines"
    assert width_of(fit("日本語のテキスト", 7)) <= 7


def test_live_line_stays_below_printed_lines():
    console = Console(TTY(), TTY(), environ={}, platform="linux")
    console.live("working")
    console.print("an alert")
    console.print("a warning", err=True)
    console.clear_live()
    out = console.out.getvalue()
    assert out.startswith("working")
    assert out.count("\r\033[2K") == 3  # erased before each print, and at the end
    assert out.rstrip("\r\033[2K").endswith("working")
    assert console.err.getvalue() == "a warning\n"


def test_spinner_draws_and_clears():
    console = Console(TTY(), environ={}, platform="linux")
    progress = AnalysisProgress(console, rule_count=52)
    with Spinner(console, progress.line, interval=0.001):
        progress("file", path="auth.log", index=0, total=2)
        progress("parsed", path="auth.log", events=29)
        progress("match", done=10, total=29)
        for _ in range(200):  # let the thread draw a frame
            if "Running 52 rules" in console.out.getvalue():
                break
            threading.Event().wait(0.01)
    out = console.out.getvalue()
    assert "Running 52 rules" in out and "10/29 events" in out
    assert out.endswith("\r\033[2K")


def test_spinner_is_silent_on_plain_output():
    console = Console(io.StringIO(), environ={})
    with Spinner(console, lambda frame: "x"):
        pass
    assert console.out.getvalue() == ""


def test_progress_line_fits_the_terminal(monkeypatch):
    monkeypatch.setattr(
        term.shutil, "get_terminal_size", lambda fallback: os.terminal_size((50, 20))
    )
    console = Console(TTY(), environ={}, platform="linux")
    progress = AnalysisProgress(console, rule_count=52)
    progress("file", path="a/very/long/path/" * 10 + "auth.log", index=3, total=67)
    progress("parsed", path="x", events=1429)
    assert width_of(progress.line("*")) <= 49


def box(console, **extra):
    parts = dict(
        headline=(94, "alerts to review"),
        counts={"critical": 0, "high": 39, "medium": 47, "low": 8},
        notes=["25 below low not shown"],
        top=[TopAlert("high", "LSASS Memory Access With Credential Dumping Rights", 9, ("T1003",))],
        footer="1,429 events from 67 file(s), 52 rules, 0.4 s",
    )
    parts.update(extra)
    return parts


def test_summary_box_is_a_closed_frame():
    console = Console(TTY(), environ={}, platform="linux")
    lines = summary_box(console, **box(console))
    widths = {width_of(line) for line in lines}
    assert len(widths) == 1
    text = "\n".join(lines)
    assert " HIGH " in text and "39" in text and "LSASS Memory Access" in text and "T1003" in text
    assert lines[0].count("╭") == 1 and lines[-1].count("╯") == 1


def test_summary_counts_up_then_lands_on_the_totals():
    console = Console(TTY(), environ={}, platform="linux")
    show_summary(console, **box(console))
    out = console.out.getvalue()
    assert "\033[" in out and "F" in out  # redrawn in place
    final = summary_box(console, **box(console))
    assert out.endswith("\033[2K" + final[-1] + "\n")
    assert "\033[1m0\033[0m alerts to review" in out  # the first frame starts at zero


def test_summary_is_drawn_once_without_animation():
    console = Console(AsciiTTY(), environ={}, platform="linux")
    show_summary(console, animate=False, **box(console))
    out = console.out.getvalue()
    assert out.count("Summary") == 1 and "+--" in out


def test_toast():
    console = Console(TTY(), environ={}, platform="linux")
    line = toast(
        console,
        when="2024-03-10 09:07:05Z",
        level="informational",
        title="SSH Login Accepted",
        techniques="T1021.004",
        what="user=deploy " * 40,
    )
    assert " INFO " in line and "SSH Login Accepted" in line and "T1021.004" in line
    assert width_of(line) <= console.width
