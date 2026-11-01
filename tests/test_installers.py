"""The double-click installers at the root of the repository.

The shell installer (macOS and Linux) runs here in a temporary home, with fake
Python interpreters to test how it finds one. The Windows scripts cannot run
on the CI's Linux and macOS machines: they get static checks of what matters
(Python detection order, no remote code, characters Windows PowerShell 5.1
reads right). A full install with pip, which needs the network, runs when
VIGIE_TEST_INSTALLER=1.
"""

import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
INSTALLER = ROOT / "installer" / "install.sh"
UNINSTALLER = ROOT / "installer" / "uninstall.sh"
SHELL_SCRIPTS = [
    INSTALLER,
    UNINSTALLER,
    ROOT / "install-linux.sh",
    ROOT / "uninstall-linux.sh",
    ROOT / "Install Vigie (macOS).command",
    ROOT / "Uninstall Vigie (macOS).command",
]
# The macOS and Linux installers run with bash. On Windows, "bash" is often the
# WSL launcher with no Linux inside, so those tests run elsewhere only.
needs_bash = pytest.mark.skipif(
    sys.platform == "win32" or shutil.which("bash") is None,
    reason="the macOS and Linux installers need bash on macOS or Linux",
)


def fake_python(folder, name, *, version_ok=True, venv_ok=True):
    """A script answering the installer's check like a Python of some version would."""
    path = folder / name
    ok = "0" if version_ok and venv_ok else "1"
    path.write_text(f"#!/bin/sh\nexit {ok}\n", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return path


def bash(script, *, env=None, cwd=ROOT):
    return subprocess.run(
        ["bash", "-c", script],
        capture_output=True,
        text=True,
        env={"PATH": os.environ["PATH"], "HOME": os.environ.get("HOME", "/tmp"), **(env or {})},
        cwd=cwd,
        timeout=60,
        check=False,
    )


@needs_bash
@pytest.mark.parametrize("script", SHELL_SCRIPTS, ids=lambda path: path.name)
def test_shell_scripts_parse_and_are_executable(script):
    assert subprocess.run(["bash", "-n", str(script)], check=False).returncode == 0
    assert os.access(script, os.X_OK)
    assert b"\r\n" not in script.read_bytes()


@needs_bash
def test_finds_the_first_recent_python(tmp_path):
    old = fake_python(tmp_path, "python3.9", version_ok=False)
    new = fake_python(tmp_path, "python3.12")
    result = bash(
        "VIGIE_INSTALLER_SOURCE_ONLY=1 . installer/install.sh; find_python",
        env={"VIGIE_PYTHON_CANDIDATES": f"{tmp_path / 'missing'} {old} {new} {sys.executable}"},
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == str(new)


@needs_bash
def test_finds_python_on_the_path(tmp_path):
    fake_python(tmp_path, "python3")
    result = bash(
        "VIGIE_INSTALLER_SOURCE_ONLY=1 . installer/install.sh; find_python",
        env={"VIGIE_PYTHON_CANDIDATES": "python3.99 python3", "PATH": f"{tmp_path}:/usr/bin:/bin"},
    )
    assert result.stdout.strip() == str(tmp_path / "python3")


@needs_bash
def test_without_python_it_opens_the_download_page(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_python(bin_dir, "python3", version_ok=False)
    opened = tmp_path / "opened.txt"
    for opener in ("xdg-open", "open"):
        tool = bin_dir / opener
        tool.write_text(f'#!/bin/sh\necho "$@" > "{opened}"\n', encoding="utf-8")
        tool.chmod(0o755)
    result = bash(
        "bash installer/install.sh",
        env={
            "HOME": str(tmp_path),
            "PATH": f"{bin_dir}:/usr/bin:/bin",
            "VIGIE_DATA_DIR": str(tmp_path / "data"),
            "VIGIE_PYTHON_CANDIDATES": "python3",
        },
    )
    assert result.returncode == 1
    assert "Vigie needs Python 3.10 or later" in result.stdout
    assert "double-click this installer again" in result.stdout
    assert "Traceback" not in result.stdout + result.stderr
    assert opened.read_text().strip() == "https://www.python.org/downloads/"
    assert "no suitable Python found" in (tmp_path / "data" / "install.log").read_text()


@needs_bash
def test_uninstall_removes_only_what_vigie_made(tmp_path):
    desktop = tmp_path / "Desktop"
    desktop.mkdir()
    (desktop / "vigie.desktop").write_text("Exec=/x/python -m vigie ui\n", encoding="utf-8")
    other = tmp_path / ".local" / "share" / "applications"
    other.mkdir(parents=True)
    (other / "vigie.desktop").write_text("Exec=someone-else\n", encoding="utf-8")
    venv = tmp_path / "data" / "venv"
    venv.mkdir(parents=True)
    (tmp_path / "data" / "reports").mkdir()
    result = bash(
        "bash installer/uninstall.sh",
        env={"HOME": str(tmp_path), "VIGIE_DATA_DIR": str(tmp_path / "data")},
    )
    assert result.returncode == 0, result.stderr
    assert not (desktop / "vigie.desktop").exists()
    assert (other / "vigie.desktop").exists()
    assert not venv.exists()
    assert (tmp_path / "data" / "reports").exists()
    assert "Your reports are still in" in result.stdout


@needs_bash
@pytest.mark.skipif(
    os.environ.get("VIGIE_TEST_INSTALLER") != "1", reason="set VIGIE_TEST_INSTALLER=1"
)
def test_full_install_then_uninstall(tmp_path):
    (tmp_path / "Desktop").mkdir()
    env = {
        **{
            k: v
            for k, v in os.environ.items()
            if "PROXY" in k or k.endswith(("_CERT", "CA_BUNDLE", "CERT_FILE"))
        },
        "HOME": str(tmp_path),
        "VIGIE_DATA_DIR": str(tmp_path / "data"),
        "VIGIE_CONFIG_DIR": str(tmp_path / "config"),
        "VIGIE_INSTALL_NO_LAUNCH": "1",
        "XDG_DATA_HOME": str(tmp_path / "share"),
    }
    result = bash("bash ./install-linux.sh < /dev/null", env=env)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "is installed" in result.stdout
    python = tmp_path / "data" / "venv" / "bin" / "python"
    assert subprocess.run([str(python), "-m", "vigie", "--version"], check=False).returncode == 0
    assert "-m vigie ui" in (tmp_path / "Desktop" / "vigie.desktop").read_text()
    again = bash("bash ./install-linux.sh < /dev/null", env=env)
    assert "Updating the one already" in again.stdout
    assert bash("bash ./uninstall-linux.sh < /dev/null", env=env).returncode == 0
    assert not (tmp_path / "data" / "venv").exists()
    assert not (tmp_path / "Desktop" / "vigie.desktop").exists()


# --- Windows: static checks -------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "installer/install.ps1",
        "installer/uninstall.ps1",
        "Install Vigie (Windows).bat",
        "Uninstall Vigie (Windows).bat",
    ],
)
def test_windows_scripts_are_plain_ascii_with_crlf(name):
    data = (ROOT / name).read_bytes()
    data.decode("ascii")  # Windows PowerShell 5.1 reads files without a BOM as ANSI
    assert b"\r\n" in data and b"\n" not in data.replace(b"\r\n", b"")


@pytest.mark.parametrize("name", ["Install", "Uninstall"])
def test_bat_runs_its_script_with_bypass_for_this_run_only(name):
    text = (ROOT / f"{name} Vigie (Windows).bat").read_text(encoding="ascii")
    script = name.lower()
    assert (
        f'powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0installer\\{script}.ps1"'
        in text
    )
    assert "Set-ExecutionPolicy" not in text


@pytest.mark.parametrize("name", ["Install", "Uninstall"])
def test_bat_keeps_its_window_open_even_if_the_script_cannot_run(name):
    lines = (ROOT / f"{name} Vigie (Windows).bat").read_text(encoding="ascii").splitlines()
    # The script itself does not wait; the .bat does, so a script blocked by
    # Windows still leaves a message on screen instead of a window that flashes.
    assert 'set "VIGIE_INSTALL_NO_PAUSE=1"' in lines
    assert lines[-1] == "pause"


def test_install_sh_runs_the_system_python_isolated():
    text = (ROOT / "installer" / "install.sh").read_text(encoding="utf-8")
    assert '"$path" -I -c \'import sys, venv, ensurepip;' in text
    assert 'quietly "$python" -I -m venv "$VENV"' in text
    assert not re.search(r'"\$(path|python)" -(c|m) ', text)


def test_install_ps1():
    text = (ROOT / "installer" / "install.ps1").read_text(encoding="ascii")
    # Python: the py launcher first, then python, then python3; 3.10 or later.
    order = [text.index(f"Program = '{name}'") for name in ("py", "python", "python3")]
    assert order == sorted(order)
    assert "Extra = @('-3')" in text
    assert "sys.version_info >= (3, 10)" in text
    assert "https://www.python.org/downloads/" in text
    assert 'tick "Add python.exe to PATH"' in text
    assert "Join-Path $env:LOCALAPPDATA 'Vigie'" in text
    assert "'--force-reinstall', '--no-deps'" in text  # re-running upgrades in place
    # The system Python runs isolated, so a broken user site-packages stays out.
    assert "& $candidate.Program @extra -I -c $check" in text
    assert "& $python -I -c 'import platform" in text
    assert "@('-I', '-m', 'venv', $Venv)" in text
    assert "& $python -c" not in text
    assert "@('-m', 'vigie', 'shortcut')" in text
    assert "Scripts\\pythonw.exe" in text and "-WindowStyle Hidden" in text
    assert "install.log" in text
    # Nothing downloaded and run, no policy changed.
    for forbidden in (
        "Invoke-Expression",
        "iex ",
        "DownloadString",
        "Net.WebClient",
        "Invoke-WebRequest",
        "Set-ExecutionPolicy",
    ):
        assert forbidden not in text
    # Windows PowerShell 5.1 strips double quotes from arguments to native programs.
    for line in text.splitlines():
        if re.search(r"&\s*\$\S+.*\s-c\s", line) or "$check = " in line:
            assert '"' not in line, line
    for opening, closing in ("{}", "()"):
        assert text.count(opening) == text.count(closing)


def test_uninstall_ps1():
    text = (ROOT / "installer" / "uninstall.ps1").read_text(encoding="ascii")
    assert "-m vigie shortcut --remove" in text
    assert "[Environment]::GetFolderPath('Desktop')" in text  # follows OneDrive redirection
    assert "Remove-Item -Recurse -Force $Venv" in text
    for opening, closing in ("{}", "()"):
        assert text.count(opening) == text.count(closing)
