"""The desktop icon of the app: what is written on each system, when it is made, and removal."""

import io
import os
import plistlib
import subprocess
import sys
from pathlib import Path

import pytest

from vigie import cli, shortcut, standalone, userdirs
from vigie.cli import main
from vigie.shortcut import ShortcutError, create, first_run, remove


@pytest.fixture(autouse=True)
def config(tmp_path, monkeypatch):
    folder = tmp_path / "config"
    monkeypatch.setenv("VIGIE_CONFIG_DIR", str(folder))
    return folder


@pytest.fixture
def desktop(tmp_path):
    folder = tmp_path / "Desktop"
    folder.mkdir()
    return folder


class Runner:
    """Stands for subprocess.run; can make the file PowerShell would write."""

    def __init__(self, makes=None, error=None, returncode=0):
        self.calls = []
        self.makes, self.error, self.returncode = makes, error, returncode

    def __call__(self, command, **options):
        self.calls.append((command, options))
        if self.error:
            raise self.error
        if self.makes:
            Path(options["env"][self.makes]).write_bytes(b"L\x00\x00\x00")
        return subprocess.CompletedProcess(command, self.returncode, "", "")


# --- macOS ------------------------------------------------------------------------------


def test_macos_app_bundle(tmp_path, desktop):
    python = tmp_path / "Application Support" / "Vigie" / "venv" / "bin" / "python"
    (made,) = create(
        python=python, platform="darwin", environ={"HOME": str(tmp_path)}, desktop=desktop
    )
    assert made == desktop / "Vigie.app"
    with (made / "Contents" / "Info.plist").open("rb") as handle:
        info = plistlib.load(handle)
    assert info["CFBundleIdentifier"] == shortcut.BUNDLE_ID
    assert info["CFBundleExecutable"] == "Vigie" and info["CFBundleIconFile"] == "vigie"
    assert info["LSUIElement"] is True
    launcher = made / "Contents" / "MacOS" / "Vigie"
    assert launcher.read_text().splitlines()[-1] == f"exec '{python}' -m vigie ui \"$@\""
    assert os.access(launcher, os.X_OK)
    icns = (made / "Contents" / "Resources" / "vigie.icns").read_bytes()
    assert icns[:4] == b"icns"
    # Made again: replaced in place. Removed: gone.
    create(python=python, platform="darwin", environ={"HOME": str(tmp_path)}, desktop=desktop)
    assert remove(platform="darwin", environ={"HOME": str(tmp_path)}, desktop=desktop) == [made]
    assert not made.exists()


def test_macos_applications_folder(tmp_path, desktop):
    (made,) = create(
        python="/usr/bin/python3",
        applications=True,
        platform="darwin",
        environ={"HOME": str(tmp_path)},
        desktop=desktop,
    )
    assert made == tmp_path / "Applications" / "Vigie.app"


def test_macos_never_replaces_another_app(tmp_path, desktop):
    other = desktop / "Vigie.app" / "Contents"
    other.mkdir(parents=True)
    with (other / "Info.plist").open("wb") as handle:
        plistlib.dump({"CFBundleIdentifier": "com.example.other"}, handle)
    with pytest.raises(ShortcutError, match="not Vigie's"):
        create(
            python="/usr/bin/python3",
            platform="darwin",
            environ={"HOME": str(tmp_path)},
            desktop=desktop,
        )
    assert remove(platform="darwin", environ={"HOME": str(tmp_path)}, desktop=desktop) == []
    assert other.exists()


# --- Windows ----------------------------------------------------------------------------


def test_windows_link_made_by_powershell(tmp_path, desktop):
    python = tmp_path / "Vigie" / "venv" / "Scripts" / "python.exe"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"")
    (python.parent / "pythonw.exe").write_bytes(b"")
    run = Runner(makes="VIGIE_LINK")
    (made,) = create(
        python=python,
        platform="win32",
        environ={"USERPROFILE": str(tmp_path)},
        run=run,
        desktop=desktop,
    )
    assert made == desktop / "Vigie.lnk"
    ((command, options),) = run.calls
    assert command[:6] == [
        "powershell",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
    ]
    script = command[6]
    assert "WScript.Shell" in script and "$env:VIGIE_LINK" in script
    # Paths travel as environment variables, never pasted into the script.
    assert str(tmp_path) not in script
    env = options["env"]
    assert env["VIGIE_TARGET"] == str(python.parent / "pythonw.exe")  # no console window
    assert env["VIGIE_ARGUMENTS"] == "-m vigie ui"
    assert env["VIGIE_ICON"].endswith("vigie.ico") and Path(env["VIGIE_ICON"]).is_file()
    assert remove(platform="win32", environ={"USERPROFILE": str(tmp_path)}, desktop=desktop) == [
        made
    ]


@pytest.mark.parametrize("run", [Runner(error=OSError("no powershell")), Runner(returncode=1)])
def test_windows_falls_back_to_a_command_file(tmp_path, desktop, run):
    python = tmp_path / "python.exe"
    (made,) = create(python=python, platform="win32", environ={}, run=run, desktop=desktop)
    assert made == desktop / "Vigie.cmd"
    text = made.read_bytes().decode("utf-8")
    assert f'start "" "{python}" -m vigie ui' in text and "\r\n" in text and "\r\r" not in text
    assert remove(platform="win32", environ={}, desktop=desktop) == [made]


def test_windows_desktop_follows_redirection(monkeypatch):
    monkeypatch.setattr(userdirs, "_windows_registry_desktop", lambda: r"D:\OneDrive - Org\Desktop")
    monkeypatch.setattr(userdirs, "_windows_shell_desktop", lambda: pytest.fail("not needed"))
    assert str(userdirs.desktop_dir({}, "win32")) == r"D:\OneDrive - Org\Desktop"
    monkeypatch.setattr(userdirs, "_windows_registry_desktop", lambda: None)
    monkeypatch.setattr(userdirs, "_windows_shell_desktop", lambda: r"E:\Users\me\Desktop")
    assert str(userdirs.desktop_dir({}, "win32")) == r"E:\Users\me\Desktop"
    monkeypatch.setattr(userdirs, "_windows_shell_desktop", lambda: None)
    assert userdirs.desktop_dir({"USERPROFILE": "/users/me"}, "win32") == Path("/users/me/Desktop")


def test_windows_lookups_fail_quietly_elsewhere(monkeypatch):
    if sys.platform != "win32":
        assert userdirs._windows_registry_desktop() is None  # no winreg here
    monkeypatch.setattr(userdirs.subprocess, "run", Runner(error=FileNotFoundError("powershell")))
    assert userdirs._windows_shell_desktop() is None


# --- Linux --------------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform == "win32", reason="desktop entries are a Linux file format")
def test_linux_desktop_entries(tmp_path, desktop):
    run = Runner()
    python = tmp_path / "my env" / "bin" / "python"
    env = {"HOME": str(tmp_path), "XDG_DATA_HOME": str(tmp_path / "share")}
    made = create(python=python, platform="linux", environ=env, run=run, desktop=desktop)
    assert made == [
        tmp_path / "share" / "applications" / "vigie.desktop",
        desktop / "vigie.desktop",
    ]
    entry = made[0].read_text(encoding="utf-8")
    assert f'Exec="{python}" -m vigie ui' in entry
    assert "Terminal=false" in entry and "Icon=" in entry and entry.startswith("[Desktop Entry]")
    assert Path(entry.split("Icon=")[1].splitlines()[0]).is_file()
    assert all(os.access(path, os.X_OK) for path in made)
    assert run.calls[0][0][:2] == ["gio", "set"]
    assert remove(platform="linux", environ=env, desktop=desktop) == made


def test_linux_without_a_desktop_folder(tmp_path):
    env = {"HOME": str(tmp_path), "XDG_DATA_HOME": str(tmp_path / "share")}
    made = create(
        python="/usr/bin/python3",
        platform="linux",
        environ=env,
        run=Runner(),
        desktop=tmp_path / "none",
    )
    assert made == [tmp_path / "share" / "applications" / "vigie.desktop"]


def test_desktop_quoting():
    assert shortcut._desktop_quote("/usr/bin/python3") == "/usr/bin/python3"
    assert shortcut._desktop_quote('/a b/"$x`\\') == '"/a b/\\"\\$x\\`\\\\"'


def test_linux_desktop_folder_from_xdg(monkeypatch, tmp_path):
    monkeypatch.setattr(userdirs, "_xdg_desktop", lambda home: tmp_path / "Bureau")
    assert userdirs.desktop_dir({"HOME": str(tmp_path)}, "linux") == tmp_path / "Bureau"
    monkeypatch.setattr(userdirs, "_xdg_desktop", lambda home: None)
    assert userdirs.desktop_dir({"HOME": str(tmp_path)}, "linux") == tmp_path / "Desktop"


def test_remove_leaves_other_files_alone(tmp_path, desktop):
    (desktop / "vigie.desktop").write_text(
        "[Desktop Entry]\nExec=something else\n", encoding="utf-8"
    )
    env = {"HOME": str(tmp_path), "XDG_DATA_HOME": str(tmp_path / "share")}
    assert remove(platform="linux", environ=env, desktop=desktop) == []
    assert (desktop / "vigie.desktop").exists()


# --- The first run ------------------------------------------------------------------------


class TTY(io.StringIO):
    def isatty(self):
        return True


def test_first_run_makes_the_icon_once(tmp_path, config):
    made, err = [], io.StringIO()

    def make():
        made.append(1)
        return [tmp_path / "Desktop" / "Vigie.app"]

    assert first_run(err, stdout=TTY(), environ={}, modules={}, make=make)
    assert made == [1]
    line = err.getvalue()
    assert line.count("\n") == 1 and "vigie shortcut --remove" in line and "Vigie.app" in line
    # Never again, even after the user deleted the icon.
    assert first_run(err, stdout=TTY(), environ={}, modules={}, make=make) == []
    assert made == [1]
    assert userdirs.load_config()["shortcut_offered"]


@pytest.mark.parametrize(
    ("stdout", "environ", "modules"),
    [
        (io.StringIO(), {}, {}),
        (TTY(), {"CI": "true"}, {}),
        (TTY(), {"VIGIE_NO_SHORTCUT": "1"}, {}),
        (TTY(), {"PYTEST_CURRENT_TEST": "x"}, {}),
        (TTY(), {}, {"pytest": object()}),
    ],
)
def test_first_run_opt_outs(stdout, environ, modules):
    err = io.StringIO()
    assert (
        first_run(
            err,
            stdout=stdout,
            environ=environ,
            modules=modules,
            make=lambda: pytest.fail("must not run"),
        )
        == []
    )
    assert err.getvalue() == ""
    assert userdirs.load_config() == {}


def test_first_run_failure_is_one_line_and_not_retried():
    err = io.StringIO()

    def broken():
        raise ShortcutError("no Desktop")

    assert first_run(err, stdout=TTY(), environ={}, modules={}, make=broken) == []
    assert (
        err.getvalue() == "Vigie could not add a desktop icon (no Desktop); try: vigie shortcut\n"
    )
    assert userdirs.load_config()["shortcut_offered"]


def test_making_the_icon_by_hand_counts_as_the_first_run(tmp_path, desktop):
    create(
        python="/usr/bin/python3",
        platform="linux",
        environ={"HOME": str(tmp_path), "XDG_DATA_HOME": str(tmp_path / "s")},
        run=Runner(),
        desktop=desktop,
    )
    assert (
        first_run(
            io.StringIO(),
            stdout=TTY(),
            environ={},
            modules={},
            make=lambda: pytest.fail("already made"),
        )
        == []
    )


def test_commands_run_the_first_run_but_never_fail_on_it(monkeypatch, capsys):
    calls = []

    def first(err):
        calls.append(err)
        raise RuntimeError("unexpected")

    monkeypatch.setattr(shortcut, "first_run", first)
    assert main(["rules"]) == 0
    assert len(calls) == 1
    calls.clear()
    monkeypatch.setattr(shortcut, "create", lambda **kw: [Path("/x/Vigie.lnk")])
    assert main(["shortcut"]) == 0
    assert calls == []  # vigie shortcut does its own job
    assert f"Created {Path('/x/Vigie.lnk')}" in capsys.readouterr().out


def test_shortcut_command(monkeypatch, capsys):
    monkeypatch.setattr(shortcut, "remove", lambda: [Path("/d/Vigie.app")])
    assert main(["shortcut", "--remove"]) == 0
    assert capsys.readouterr().out == f"Removed {Path('/d/Vigie.app')}\n"
    monkeypatch.setattr(shortcut, "remove", list)
    assert main(["shortcut", "--remove"]) == 0
    assert "No Vigie icon to remove." in capsys.readouterr().out

    def refuse(**options):
        raise ShortcutError("/d/Vigie.app exists and is not Vigie's")

    monkeypatch.setattr(shortcut, "create", refuse)
    assert main(["shortcut"]) == 2
    assert "could not add the icon" in capsys.readouterr().err


# --- The standalone program -------------------------------------------------------------------


@pytest.fixture
def frozen(monkeypatch, tmp_path):
    """Vigie as the program PyInstaller builds: no Python, the program opens the app itself."""
    program = tmp_path / "Downloads" / "Vigie" / "Vigie.exe"
    program.parent.mkdir(parents=True)
    program.write_bytes(b"MZ")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(program))
    return program


def test_app_command():
    assert shortcut.app_command("/usr/bin/python3") == (
        Path("/usr/bin/python3"),
        ["-m", "vigie", "ui"],
    )
    assert shortcut.app_command() == (Path(sys.executable), ["-m", "vigie", "ui"])


def test_app_command_of_the_standalone_program(frozen):
    assert shortcut.app_command() == (frozen, ["ui"])
    # A Python given on purpose still runs Vigie as a module.
    assert shortcut.app_command("/usr/bin/python3")[1] == ["-m", "vigie", "ui"]


def test_standalone_windows_link_opens_the_program(frozen, desktop):
    run = Runner(makes="VIGIE_LINK")
    (made,) = create(platform="win32", environ={}, run=run, desktop=desktop)
    assert made == desktop / "Vigie.lnk"
    ((_command, options),) = run.calls
    env = options["env"]
    assert env["VIGIE_TARGET"] == str(frozen) and env["VIGIE_ARGUMENTS"] == "ui"
    assert env["VIGIE_ICON"] == str(frozen)  # the program carries the icon
    # PowerShell runs without a console window of its own, and reads nothing.
    assert options["creationflags"] == shortcut.NO_WINDOW
    assert options["stdin"] == subprocess.DEVNULL
    assert remove(platform="win32", environ={}, desktop=desktop) == [made]


def test_standalone_windows_command_file(frozen, desktop):
    (made,) = create(platform="win32", environ={}, run=Runner(returncode=1), desktop=desktop)
    assert made == desktop / "Vigie.cmd"
    text = made.read_bytes().decode("utf-8")
    assert f'start "" "{frozen}" ui\r\n' in text and "-m vigie" not in text
    assert remove(platform="win32", environ={}, desktop=desktop) == [made]


def test_standalone_macos_app_needs_no_icon(frozen, tmp_path, desktop):
    with pytest.raises(ShortcutError, match="is the app itself"):
        create(platform="darwin", environ={"HOME": str(tmp_path)}, desktop=desktop)
    assert list(desktop.iterdir()) == []


@pytest.mark.skipif(sys.platform == "win32", reason="desktop entries are a Linux file format")
def test_standalone_linux_entry(frozen, tmp_path, desktop):
    env = {"HOME": str(tmp_path), "XDG_DATA_HOME": str(tmp_path / "share")}
    made = create(platform="linux", environ=env, run=Runner(), desktop=desktop)
    entry = made[0].read_text(encoding="utf-8")
    assert f"Exec={frozen} ui\n" in entry and "-m vigie" not in entry
    assert remove(platform="linux", environ=env, desktop=desktop) == made


def test_removing_the_icon_never_removes_the_standalone_app(tmp_path, desktop):
    app = desktop / "Vigie.app" / "Contents"
    app.mkdir(parents=True)
    with (app / "Info.plist").open("wb") as handle:
        plistlib.dump({"CFBundleIdentifier": standalone.BUNDLE_ID}, handle)
    assert remove(platform="darwin", environ={"HOME": str(tmp_path)}, desktop=desktop) == []
    with pytest.raises(ShortcutError, match="not Vigie's"):
        create(
            python="/usr/bin/python3",
            platform="darwin",
            environ={"HOME": str(tmp_path)},
            desktop=desktop,
        )
    assert (app / "Info.plist").is_file()


def test_first_run_of_the_standalone_program_needs_no_terminal(frozen, monkeypatch):
    made, err = [], io.StringIO()
    monkeypatch.setattr(sys, "stdout", None)  # a program without a console window
    icon = Path("C:/Users/me/Desktop/Vigie.lnk")

    def make():
        made.append(1)
        return [icon]

    assert first_run(err, environ={}, modules={}, make=make, platform="win32") == [icon]
    assert made == [1]
    assert "Vigie.exe shortcut --remove" in err.getvalue()
    assert first_run(err, environ={}, modules={}, make=make, platform="win32") == []
    assert made == [1]


@pytest.mark.parametrize(
    ("environ", "modules"),
    [({"CI": "true"}, {}), ({"VIGIE_NO_SHORTCUT": "1"}, {}), ({}, {"pytest": object()})],
)
def test_first_run_of_the_standalone_program_keeps_the_opt_outs(frozen, environ, modules):
    assert (
        first_run(
            io.StringIO(),
            stdout=io.StringIO(),
            environ=environ,
            modules=modules,
            make=lambda: pytest.fail("must not run"),
            platform="win32",
        )
        == []
    )
    assert userdirs.load_config() == {}


def test_first_run_of_the_standalone_macos_app_adds_nothing(frozen):
    assert (
        first_run(
            io.StringIO(),
            stdout=TTY(),
            environ={},
            modules={},
            make=lambda: pytest.fail("Vigie.app is the icon"),
            platform="darwin",
        )
        == []
    )
    assert userdirs.load_config() == {}


# --- Folders ---------------------------------------------------------------------------------


def test_user_folders_per_system(tmp_path):
    home = {"HOME": "/h"}
    assert userdirs.data_dir(home, "darwin") == Path("/h/Library/Application Support/Vigie")
    assert userdirs.config_dir(home, "darwin") == Path("/h/Library/Application Support/Vigie")
    win = {"LOCALAPPDATA": "C:/L", "APPDATA": "C:/R"}
    assert userdirs.data_dir(win, "win32") == Path("C:/L/Vigie")
    assert userdirs.config_dir(win, "win32") == Path("C:/R/Vigie")
    assert userdirs.data_dir(home, "linux") == Path("/h/.local/share/vigie")
    assert userdirs.config_dir(home, "linux") == Path("/h/.config/vigie")
    assert userdirs.data_dir({"VIGIE_DATA_DIR": str(tmp_path)}, "linux") == tmp_path
    xdg = {"HOME": "/h", "XDG_DATA_HOME": "/x/d", "XDG_CONFIG_HOME": "/x/c"}
    assert userdirs.data_dir(xdg, "linux") == Path("/x/d/vigie")
    assert userdirs.config_dir(xdg, "linux") == Path("/x/c/vigie")


def test_config_file_survives_garbage(config):
    config.mkdir(parents=True)
    (config / "config.json").write_text("[1, 2", encoding="utf-8")
    assert userdirs.load_config() == {}
    userdirs.save_config({"a": 1})
    userdirs.save_config({"b": 2})
    assert userdirs.load_config() == {"a": 1, "b": 2}


def test_cli_module_has_no_stray_first_run_in_tests():
    # Under pytest, the first run never creates anything.
    assert "pytest" in sys.modules
    assert cli._first_run() is None
