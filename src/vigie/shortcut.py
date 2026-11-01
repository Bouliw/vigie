"""A desktop icon that opens the Vigie app (``vigie ui``) without a terminal window.

* macOS: a small ``Vigie.app`` bundle on the Desktop (or in ``~/Applications``):
  an ``Info.plist``, a launcher script that runs this Python with ``-m vigie ui``,
  and the icon.
* Windows: a ``Vigie.lnk`` shortcut on the Desktop, made with the WScript.Shell
  COM object through PowerShell, that runs ``pythonw.exe -m vigie ui`` (no
  console window). If that fails, a ``Vigie.cmd`` file does the same.
* Linux: a ``vigie.desktop`` entry in the applications menu and on the Desktop.

The standalone program (see :mod:`vigie.standalone`) has no Python to run: its
icon opens the program itself, ``Vigie.exe ui``. On macOS that program is a
``Vigie.app`` already, and needs no other icon.

The first time a ``vigie`` command runs in a terminal, it creates the icon once
(see :func:`first_run`); ``vigie shortcut --remove`` takes it away for good.
"""

from __future__ import annotations

import contextlib
import os
import plistlib
import shutil
import stat
import subprocess
import sys
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO

from vigie import __version__
from vigie.icons import ICONS_DIR
from vigie.standalone import is_frozen
from vigie.userdirs import desktop_dir, load_config, save_config

BUNDLE_ID = "io.github.bouliw.vigie"
# Every launcher file Vigie writes says so, which is how it knows the files it may remove.
MARK = "Opens the Vigie app."
# The standalone program has no console of its own: PowerShell must not open one either.
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
LNK_SCRIPT = """\
$shell = New-Object -ComObject WScript.Shell
$link = $shell.CreateShortcut($env:VIGIE_LINK)
$link.TargetPath = $env:VIGIE_TARGET
$link.Arguments = $env:VIGIE_ARGUMENTS
$link.WorkingDirectory = $env:USERPROFILE
$link.IconLocation = $env:VIGIE_ICON + ',0'
$link.Description = 'Open Vigie, the log analyzer'
$link.Save()
"""

Runner = Callable[..., subprocess.CompletedProcess]


class ShortcutError(Exception):
    """The icon could not be created or removed."""


def app_command(python: str | Path | None = None) -> tuple[Path, list[str]]:
    """The program and the arguments that open the Vigie app.

    That is ``python -m vigie ui``, this Python by default, or the standalone
    program itself with ``ui`` when Vigie runs as one.
    """
    if python is None and is_frozen():
        return Path(sys.executable), ["ui"]
    return Path(python or sys.executable), ["-m", "vigie", "ui"]


def create(
    *,
    python: str | Path | None = None,
    applications: bool = False,
    platform: str | None = None,
    environ: Mapping[str, str] | None = None,
    run: Runner = subprocess.run,
    desktop: Path | None = None,
) -> list[Path]:
    """Create the icon for this platform; return the files made."""
    platform = platform or sys.platform
    env = os.environ if environ is None else environ
    standalone = python is None and is_frozen()
    if standalone and platform == "darwin":
        raise ShortcutError(
            "this Vigie.app is the app itself: keep it in Applications, or drag it to the Dock"
        )
    program, arguments = app_command(python)
    folder = desktop or desktop_dir(env, platform)
    if platform == "darwin":
        home = Path(env.get("HOME") or Path.home())
        target = home / "Applications" if applications else folder
        made = [_mac_app(target / "Vigie.app", program, arguments)]
    elif platform == "win32":
        made = [_windows_link(folder, program, arguments, env, run, standalone=standalone)]
    else:
        made = _linux_entries(folder, program, arguments, env, run)
    _remember(made)
    return made


def remove(
    *,
    platform: str | None = None,
    environ: Mapping[str, str] | None = None,
    desktop: Path | None = None,
) -> list[Path]:
    """Remove every icon Vigie may have created; return what was removed."""
    platform = platform or sys.platform
    env = os.environ if environ is None else environ
    folder = desktop or desktop_dir(env, platform)
    home = Path(env.get("HOME") or Path.home())
    candidates = [Path(path) for path in load_config().get("shortcut_files", [])]
    if platform == "darwin":
        candidates += [folder / "Vigie.app", home / "Applications" / "Vigie.app"]
    elif platform == "win32":
        candidates += [folder / "Vigie.lnk", folder / "Vigie.cmd"]
    else:
        candidates += [folder / "vigie.desktop", _applications_dir(env) / "vigie.desktop"]
    removed = []
    for path in dict.fromkeys(candidates):
        if path.suffix == ".app" and path.is_dir():
            if not _is_our_bundle(path):
                continue
            shutil.rmtree(path)
            removed.append(path)
        elif path.is_file() and _is_ours(path):
            path.unlink()
            removed.append(path)
    save_config({"shortcut_files": [], "shortcut_removed": _now()})
    return removed


def first_run(
    err: TextIO,
    *,
    stdout: TextIO | None = None,
    environ: Mapping[str, str] | None = None,
    modules: Mapping[str, Any] | None = None,
    make: Callable[[], list[Path]] = create,
    platform: str | None = None,
) -> list[Path]:
    """Create the desktop icon the first time Vigie runs in a terminal, and say so in one line.

    It happens once: the settings file records it, so an icon the user deleted
    is never made again. Skipped when the output is not a terminal, in CI, with
    ``VIGIE_NO_SHORTCUT=1`` and under pytest. The standalone program has no
    terminal: it makes its icon the first time it is opened, with the same
    exceptions, except on macOS, where that program is an app with its icon.
    """
    env = os.environ if environ is None else environ
    loaded = sys.modules if modules is None else modules
    standalone = is_frozen()
    if standalone and (platform or sys.platform) == "darwin":
        return []
    command = Path(sys.executable).name if standalone else "vigie"
    out = stdout or sys.stdout
    try:
        terminal = bool(out is not None and out.isatty())
    except ValueError:
        terminal = False
    if (
        not (terminal or standalone)
        or env.get("VIGIE_NO_SHORTCUT") == "1"
        or env.get("CI")
        or "PYTEST_CURRENT_TEST" in env
        or "pytest" in loaded
    ):
        return []
    try:
        if load_config().get("shortcut_offered"):
            return []
        save_config({"shortcut_offered": _now()})
        made = make()
    except (OSError, ShortcutError) as exc:
        print(f"Vigie could not add a desktop icon ({exc}); try: {command} shortcut", file=err)
        return []
    print(
        f"Vigie added an icon to open its app: {made[-1]}. "
        f"Remove it with: {command} shortcut --remove",
        file=err,
    )
    return made


# --- macOS ------------------------------------------------------------------------


def _mac_app(app: Path, program: Path, arguments: list[str]) -> Path:
    if app.exists():
        if not _is_our_bundle(app):
            raise ShortcutError(f"{app} exists and is not Vigie's")
        shutil.rmtree(app)
    contents = app / "Contents"
    (contents / "MacOS").mkdir(parents=True)
    (contents / "Resources").mkdir()
    info = {
        "CFBundleName": "Vigie",
        "CFBundleDisplayName": "Vigie",
        "CFBundleIdentifier": BUNDLE_ID,
        "CFBundleExecutable": "Vigie",
        "CFBundleIconFile": "vigie",
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": __version__,
        "CFBundleVersion": __version__,
        "LSMinimumSystemVersion": "10.13",
        # A background helper: it serves the app to the browser, with no Dock icon.
        "LSUIElement": True,
        "NSHighResolutionCapable": True,
    }
    with (contents / "Info.plist").open("wb") as handle:
        plistlib.dump(info, handle)
    launcher = contents / "MacOS" / "Vigie"
    command = " ".join([_sh_quote(str(program)), *arguments])
    launcher.write_text(f'#!/bin/sh\n# {MARK}\nexec {command} "$@"\n', encoding="utf-8")
    _make_executable(launcher)
    shutil.copyfile(ICONS_DIR / "vigie.icns", contents / "Resources" / "vigie.icns")
    return app


def _is_our_bundle(app: Path) -> bool:
    try:
        with (app / "Contents" / "Info.plist").open("rb") as handle:
            return plistlib.load(handle).get("CFBundleIdentifier") == BUNDLE_ID
    except (OSError, plistlib.InvalidFileException, ValueError):
        return False


# --- Windows ----------------------------------------------------------------------


def _windows_link(
    folder: Path,
    program: Path,
    arguments: list[str],
    env: Mapping[str, str],
    run: Runner,
    *,
    standalone: bool = False,
) -> Path:
    if standalone:
        # The standalone program opens no console window, and carries the icon itself.
        target, icon = program, program
    else:
        pythonw = program.with_name("pythonw.exe")
        target = pythonw if pythonw.exists() else program
        icon = ICONS_DIR / "vigie.ico"
    folder.mkdir(parents=True, exist_ok=True)
    link = folder / "Vigie.lnk"
    variables = {
        **env,
        "VIGIE_LINK": str(link),
        "VIGIE_TARGET": str(target),
        "VIGIE_ARGUMENTS": " ".join(arguments),
        "VIGIE_ICON": str(icon),
    }
    command = [
        "powershell",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        LNK_SCRIPT,
    ]
    try:
        result = run(
            command,
            env=variables,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=60,
            creationflags=NO_WINDOW,
        )
        if result.returncode == 0 and link.exists():
            return link
    except (OSError, subprocess.SubprocessError):
        pass
    # No PowerShell or COM: a command file that starts the app the same way.
    fallback = folder / "Vigie.cmd"
    command_line = " ".join([f'start "" "{target}"', *arguments])
    # newline="": the line endings are already Windows ones, Windows must not add a CR.
    fallback.write_text(
        f"@echo off\r\nrem {MARK}\r\n{command_line}\r\n", encoding="utf-8", newline=""
    )
    return fallback


# --- Linux ------------------------------------------------------------------------


def _applications_dir(env: Mapping[str, str]) -> Path:
    home = Path(env.get("HOME") or Path.home())
    return Path(env.get("XDG_DATA_HOME") or home / ".local" / "share") / "applications"


def _linux_entries(
    folder: Path, program: Path, arguments: list[str], env: Mapping[str, str], run: Runner
) -> list[Path]:
    entry = "\n".join(
        [
            "[Desktop Entry]",
            f"# {MARK}",
            "Type=Application",
            "Name=Vigie",
            "Comment=Analyze logs with Sigma rules, mapped to MITRE ATT&CK and ATLAS",
            "Exec=" + " ".join([_desktop_quote(str(program)), *arguments]),
            f"Icon={ICONS_DIR / 'vigie-256.png'}",
            "Terminal=false",
            "Categories=Utility;Security;",
            "StartupNotify=false",
            "",
        ]
    )
    made = []
    for path in (_applications_dir(env) / "vigie.desktop", folder / "vigie.desktop"):
        if path.parent == folder and not folder.is_dir():
            continue  # no Desktop folder (a server): the menu entry is enough
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(entry, encoding="utf-8")
        _make_executable(path)
        made.append(path)
    # GNOME runs a launcher on the Desktop only once it is marked as trusted.
    if len(made) > 1:
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            run(
                ["gio", "set", str(made[1]), "metadata::trusted", "true"],
                capture_output=True,
                timeout=10,
            )
    return made


def _desktop_quote(value: str) -> str:
    """A value for the Exec key of a desktop entry, quoted per the specification."""
    if not any(char in value for char in ' \t"`$\\'):
        return value
    escaped = "".join("\\" + char if char in '"`$\\' else char for char in value)
    return f'"{escaped}"'


# --- Shared -----------------------------------------------------------------------


def _sh_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def _make_executable(path: Path) -> None:
    mode = path.stat().st_mode
    path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _is_ours(path: Path) -> bool:
    """Only files Vigie wrote are removed: they carry its mark, or are its .lnk.

    Icons made before the mark existed run ``-m vigie ui``.
    """
    if path.suffix == ".lnk":
        return path.name == "Vigie.lnk"
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return MARK in text or "-m vigie ui" in text


def _remember(made: list[Path]) -> None:
    now = _now()
    save_config(
        {
            "shortcut_files": [str(path) for path in made],
            "shortcut_created": now,
            # Made by hand or by an installer: the first run has nothing more to do.
            "shortcut_offered": load_config().get("shortcut_offered") or now,
        }
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
