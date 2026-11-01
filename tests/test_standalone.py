"""The standalone program built by PyInstaller: what a double-click does, and no console."""

import subprocess
import sys
from pathlib import Path

import pytest

from vigie import cli, standalone
from vigie.standalone import detach, give_streams, is_frozen, open_log


@pytest.fixture
def commands(monkeypatch):
    """The ``vigie`` commands the program runs, instead of running them."""
    calls = []

    def run(args):
        calls.append(args)
        return 0

    monkeypatch.setattr(cli, "main", run)
    return calls


@pytest.fixture
def frozen(monkeypatch, tmp_path):
    program = tmp_path / "Vigie.app" / "Contents" / "MacOS" / "Vigie"
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(program))
    return program


def test_not_frozen_under_python():
    assert not is_frozen()


def test_frozen_when_pyinstaller_says_so(frozen):
    assert is_frozen()


def test_a_double_click_opens_the_app(commands, frozen, monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    assert standalone.main([]) == 0
    assert commands == [["ui"]]


def test_arguments_make_it_the_vigie_command(commands, frozen):
    assert standalone.main(["demo", "--no-open", "-o", "out"]) == 0
    assert commands == [["demo", "--no-open", "-o", "out"]]


def test_the_finder_process_number_is_not_an_argument(commands):
    assert standalone.main(["-psn_0_12345"]) == 0
    assert commands == [["ui"]]


def test_arguments_come_from_the_command_line(commands, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["Vigie", "rules"])
    standalone.main()
    assert commands == [["rules"]]


def test_a_double_click_on_macos_serves_the_app_from_another_process(commands, frozen, monkeypatch):
    detached = []
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(standalone, "detach", lambda args: detached.append(args) or 0)
    assert standalone.main([]) == 0
    assert detached == [["ui"]] and commands == []
    # With arguments, it runs them itself.
    assert standalone.main(["ui", "--no-open"]) == 0
    assert detached == [["ui"]] and commands == [["ui", "--no-open"]]


def test_detach_starts_the_program_again_in_its_own_session(frozen, tmp_path):
    started = []

    def popen(command, **options):
        started.append((command, options))
        print("Vigie is running", file=options["stdout"])

    assert detach(["ui"], folder=tmp_path, popen=popen) == 0
    ((command, options),) = started
    assert command == [str(frozen), "ui"]
    assert options["start_new_session"] is True
    assert options["stdin"] == subprocess.DEVNULL and options["stderr"] == subprocess.STDOUT
    assert (tmp_path / "app.log").read_text(encoding="utf-8") == "Vigie is running\n"


def test_detach_failure_is_written_down(frozen, tmp_path):
    def popen(command, **options):
        raise OSError("no such program")

    assert detach(["ui"], folder=tmp_path, popen=popen) == 1
    assert "no such program" in (tmp_path / "app.log").read_text(encoding="utf-8")


def test_missing_streams_write_to_the_log(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "stdout", None)
    monkeypatch.setattr(sys, "stderr", None)
    log = give_streams(tmp_path / "data")
    try:
        assert sys.stdout is log and sys.stderr is log
        print("out")
        sys.stderr.write("err\n")
        assert not sys.stdout.isatty()
    finally:
        log.close()
    assert (tmp_path / "data" / "app.log").read_text(encoding="utf-8") == "out\nerr\n"


def test_present_streams_are_left_alone(tmp_path):
    before = sys.stdout, sys.stderr
    assert give_streams(tmp_path) is None
    assert (sys.stdout, sys.stderr) == before
    assert not (tmp_path / "app.log").exists()


def test_an_unwritable_log_is_the_null_device(tmp_path):
    blocked = tmp_path / "file"
    blocked.write_text("", encoding="utf-8")
    with open_log(blocked / "data") as log:  # a folder cannot be made inside a file
        log.write("nowhere\n")
        assert Path(log.name).name != "app.log"


def test_the_demo_runs_without_a_console(monkeypatch, tmp_path):
    monkeypatch.setenv("VIGIE_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(sys, "stdout", None)
    monkeypatch.setattr(sys, "stderr", None)
    out = tmp_path / "out"
    try:
        assert standalone.main(["demo", "--no-open", "-o", str(out)]) == 0
    finally:
        if sys.stdout is not None:
            sys.stdout.close()
    assert (out / "report.html").is_file()
    log = (tmp_path / "data" / "app.log").read_text(encoding="utf-8")
    assert "Report: " in log and "53 rules loaded" in log


def test_usage_errors_without_a_console(monkeypatch, tmp_path):
    monkeypatch.setenv("VIGIE_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(sys, "stdout", None)
    monkeypatch.setattr(sys, "stderr", None)
    try:
        assert standalone.main(["analyze", str(tmp_path / "missing")]) == 2
    finally:
        if sys.stdout is not None:
            sys.stdout.close()
    assert "no such file or directory" in (tmp_path / "data" / "app.log").read_text("utf-8")
