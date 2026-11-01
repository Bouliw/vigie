"""Vigie as one program to download and double-click, with no Python to install.

PyInstaller builds it from ``packaging/vigie.spec``: ``Vigie.exe`` on Windows, ``Vigie.app``
on macOS. Opened with no argument, by a double-click, it opens the Vigie app in the browser,
as ``vigie ui`` does. With arguments it is the ``vigie`` command, for scripts and tests:
``Vigie.exe demo --no-open -o out``.

The program has no console window. What Vigie prints goes to ``app.log`` in its data folder
(see :mod:`vigie.userdirs`), the file to look at when the app does not open.
"""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, TextIO

from vigie.userdirs import data_dir

LOG_NAME = "app.log"
# Not the identifier of the small Vigie.app that `vigie shortcut` makes: removing that icon
# must never remove the app itself.
BUNDLE_ID = "io.github.bouliw.vigie.standalone"


def is_frozen() -> bool:
    """Whether Vigie runs as the program PyInstaller built, rather than from a Python install."""
    return bool(getattr(sys, "frozen", False))


def main(argv: Sequence[str] | None = None) -> int:
    """Open the Vigie app, or run the ``vigie`` command given in ``argv``."""
    args = list(sys.argv[1:] if argv is None else argv)
    # The Finder of older macOS versions adds a -psn_<number> argument to the apps it opens.
    args = [arg for arg in args if not arg.startswith("-psn_")]
    give_streams()
    if not args:
        if sys.platform == "darwin" and is_frozen():
            return detach(["ui"])
        args = ["ui"]
    from vigie.cli import main as vigie

    return vigie(args)


def give_streams(folder: Path | None = None) -> TextIO | None:
    """Give a program without a console somewhere to print: its log file.

    A program built without a console window starts with ``sys.stdout`` and
    ``sys.stderr`` set to None, like ``pythonw``, and writing to them would fail.
    Returns the log file when it replaced one of them.
    """
    if sys.stdout is not None and sys.stderr is not None:
        return None
    log = open_log(folder)
    if sys.stdout is None:
        sys.stdout = log
    if sys.stderr is None:
        sys.stderr = log
    return log


def open_log(folder: Path | None = None) -> TextIO:
    """``app.log``, emptied, or the null device when it cannot be written."""
    try:
        folder = folder or data_dir()
        folder.mkdir(parents=True, exist_ok=True)
        # Kept open for the life of the program: it stands for its output.
        return open(
            folder / LOG_NAME, "w", encoding="utf-8", errors="backslashreplace", buffering=1
        )
    except OSError:
        return open(os.devnull, "w", encoding="utf-8")


def detach(
    args: Sequence[str],
    *,
    folder: Path | None = None,
    popen: Callable[..., Any] = subprocess.Popen,
) -> int:
    """Run this program again with ``args``, in the background, and return at once.

    macOS hands a second double-click on an app that is still running to that
    app instead of starting it again. Vigie serves its pages and shows no window,
    so that click would do nothing. The program macOS opens therefore starts the
    server in a process of its own, which macOS does not count as the app, and
    quits: every double-click opens the app in the browser.
    """
    with open_log(folder) as log:
        try:
            popen(
                [sys.executable, *args],
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                close_fds=True,
            )
        except OSError as exc:
            print(f"Vigie could not start: {exc}", file=log)
            return 1
    return 0
