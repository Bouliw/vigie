"""Where Vigie keeps its own files for a user: settings, reports made in the app, the desktop icon.

==========  ==========================================  =====================================
System      Data (app reports, installer venv and log)  Settings (``config.json``)
==========  ==========================================  =====================================
macOS       ``~/Library/Application Support/Vigie``     same folder
Windows     ``%LOCALAPPDATA%\\Vigie``                    ``%APPDATA%\\Vigie``
Linux       ``$XDG_DATA_HOME/vigie`` (~/.local/share)   ``$XDG_CONFIG_HOME/vigie`` (~/.config)
==========  ==========================================  =====================================

``VIGIE_DATA_DIR`` and ``VIGIE_CONFIG_DIR`` override them (tests, portable use).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any


def data_dir(environ: Mapping[str, str] | None = None, platform: str | None = None) -> Path:
    env = os.environ if environ is None else environ
    if env.get("VIGIE_DATA_DIR"):
        return Path(env["VIGIE_DATA_DIR"])
    platform = platform or sys.platform
    home = Path(env.get("HOME") or Path.home())
    if platform == "darwin":
        return home / "Library" / "Application Support" / "Vigie"
    if platform == "win32":
        base = env.get("LOCALAPPDATA") or str(home / "AppData" / "Local")
        return Path(base) / "Vigie"
    return Path(env.get("XDG_DATA_HOME") or home / ".local" / "share") / "vigie"


def config_dir(environ: Mapping[str, str] | None = None, platform: str | None = None) -> Path:
    env = os.environ if environ is None else environ
    if env.get("VIGIE_CONFIG_DIR"):
        return Path(env["VIGIE_CONFIG_DIR"])
    platform = platform or sys.platform
    home = Path(env.get("HOME") or Path.home())
    if platform == "darwin":
        return data_dir(env, platform)
    if platform == "win32":
        base = env.get("APPDATA") or str(home / "AppData" / "Roaming")
        return Path(base) / "Vigie"
    return Path(env.get("XDG_CONFIG_HOME") or home / ".config") / "vigie"


def load_config() -> dict[str, Any]:
    """The settings file, or ``{}`` when it is missing or unreadable."""
    try:
        data = json.loads((config_dir() / "config.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def save_config(changes: Mapping[str, Any]) -> None:
    """Merge ``changes`` into the settings file (written whole, then renamed into place)."""
    config = {**load_config(), **changes}
    folder = config_dir()
    folder.mkdir(parents=True, exist_ok=True)
    partial = folder / ".config.json.tmp"
    partial.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    partial.replace(folder / "config.json")


def desktop_dir(environ: Mapping[str, str] | None = None, platform: str | None = None) -> Path:
    """The user's Desktop folder, wherever it really is.

    On Windows the Desktop is often redirected (to OneDrive, or by a company
    policy): its path comes from the registry, then from the shell, before
    falling back to ``~\\Desktop``. On Linux it comes from ``xdg-user-dir``.
    """
    env = os.environ if environ is None else environ
    platform = platform or sys.platform
    home = Path(env.get("HOME") or env.get("USERPROFILE") or Path.home())
    if platform == "win32":
        for finder in (_windows_registry_desktop, _windows_shell_desktop):
            found = finder()
            if found:
                return Path(found)
        return Path(env.get("USERPROFILE") or home) / "Desktop"
    if platform != "darwin":
        found = _xdg_desktop(home)
        if found:
            return found
    return home / "Desktop"


def _windows_registry_desktop() -> str | None:
    """``HKCU\\...\\Explorer\\User Shell Folders``: the Desktop path, environment expanded."""
    try:
        import winreg  # Windows only

        key = r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as handle:  # type: ignore[attr-defined]
            value, _kind = winreg.QueryValueEx(handle, "Desktop")  # type: ignore[attr-defined]
        return os.path.expandvars(str(value)) or None
    except (ImportError, OSError):
        return None


def _windows_shell_desktop() -> str | None:
    """Ask the shell (the Shell.Application COM object, through PowerShell)."""
    command = "(New-Object -ComObject Shell.Application).Namespace(0).Self.Path"
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
            # No console window flashing up when the standalone program asks.
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        return None
    path = result.stdout.strip()
    return path if result.returncode == 0 and path else None


def _xdg_desktop(home: Path) -> Path | None:
    try:
        result = subprocess.run(
            ["xdg-user-dir", "DESKTOP"], capture_output=True, text=True, timeout=5, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    path = result.stdout.strip()
    # xdg-user-dir answers the home folder itself when no Desktop is set up.
    if result.returncode == 0 and path and Path(path) != home:
        return Path(path)
    return None
