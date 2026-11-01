import io
import json
import os
import shutil
import sys
from pathlib import Path

import pytest

from vigie import __version__, cli
from vigie.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def logs(tmp_path):
    folder = tmp_path / "logs"
    folder.mkdir()
    shutil.copy(FIXTURES / "authlog" / "auth.log", folder / "auth.log")
    shutil.copy(FIXTURES / "evtx" / "DE_1102_security_log_cleared.evtx", folder)
    return folder


def test_analyze_writes_html_and_markdown_by_default(logs, tmp_path, capsys):
    out = tmp_path / "out"
    assert main(["analyze", str(logs), "-o", str(out), "--year", "2024"]) == 0
    assert sorted(p.name for p in out.iterdir()) == ["report.html", "report.md"]
    stdout = capsys.readouterr().out
    assert (
        "Read 141 events from 2 file(s), 1 parser warning(s) listed in the report. 53 rules loaded."
        in stdout
    )
    assert "Alerts: 2 high, 3 medium, 1 low (3 below low not shown)." in stdout
    assert "SSH Login After Brute Force" in (out / "report.md").read_text(encoding="utf-8")


def test_analyze_json_and_min_level(logs, tmp_path):
    out = tmp_path / "out"
    args = ["analyze", str(logs), "-o", str(out), "--format", "json", "--min-level", "high"]
    assert main([*args, "--year", "2024"]) == 0
    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert data["min_level"] == "high"
    assert {alert["rule"]["level"] for alert in data["alerts"]} == {"high"}


def test_full_timeline(logs, tmp_path):
    out = tmp_path / "out"
    argv = ["analyze", str(logs), "-o", str(out), "--format", "json", "--full-timeline"]
    assert main(argv) == 0
    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert len(data["timeline"]) == data["event_count"] == 141


def test_utc_needs_no_time_zone_database(logs, tmp_path, monkeypatch):
    # Windows has no time zone database of its own: the default must not need one.
    def no_database(name):
        raise cli.ZoneInfoNotFoundError(name)

    monkeypatch.setattr(cli, "ZoneInfo", no_database)
    out = tmp_path / "out"
    argv = ["analyze", str(logs), "-o", str(out), "--format", "json", "--year", "2024"]
    assert main(argv) == 0
    assert main([*argv, "--tz", "utc"]) == 0
    assert main([*argv, "--tz", "Europe/Berlin"]) == 2


def test_time_zone_shifts_classic_syslog(logs, tmp_path):
    out = tmp_path / "out"
    argv = ["analyze", str(logs), "-o", str(out), "--format", "json", "--year", "2024"]
    assert main([*argv, "--tz", "Europe/Berlin"]) == 0
    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    (chain,) = [a for a in data["alerts"] if a["rule"]["title"] == "SSH Login After Brute Force"]
    assert chain["first_seen"] == "2024-03-10T08:05:42Z"  # 09:05:42 in Berlin (UTC+1)


@pytest.mark.skipif(sys.platform == "win32", reason="Windows file names are always Unicode")
def test_undecodable_text_does_not_break_the_report(tmp_path):
    folder = tmp_path / "logs"
    folder.mkdir()
    # A file name that is not valid UTF-8 decodes to a lone surrogate (PEP 383).
    name = os.fsdecode(b"auth-\xff.log")
    try:
        shutil.copy(FIXTURES / "authlog" / "auth.log", folder / name)
    except OSError as exc:  # APFS (macOS) only accepts UTF-8 file names
        pytest.skip(f"the file system rejects non UTF-8 names: {exc.strerror}")
    out = tmp_path / "out"
    argv = ["analyze", str(folder), "-o", str(out), "--format", "html,md,json"]
    assert main(argv) == 0
    for report in ("report.html", "report.md", "report.json"):
        assert "auth-\\udcff.log" in (out / report).read_text(encoding="utf-8")


def test_custom_rules_replace_the_shipped_ones(logs, tmp_path, capsys):
    rule = tmp_path / "rule.yml"
    rule.write_text(
        "title: Any Cron Session\nlevel: low\nlogsource: {product: linux, service: auth}\n"
        "detection: {sel: {program: CRON}, condition: sel}\n",
        encoding="utf-8",
    )
    out = tmp_path / "out"
    assert main(["analyze", str(logs), "-o", str(out), "--rules", str(rule)]) == 0
    assert "1 rules loaded" in capsys.readouterr().out


def _rules_folder(tmp_path, *, valid):
    folder = tmp_path / "rules"
    folder.mkdir()
    (folder / "broken.yml").write_text("title: Broken\nlevel: nope\n", encoding="utf-8")
    if valid:
        (folder / "cron.yml").write_text(
            "title: Any Cron Session\nlevel: low\nlogsource: {product: linux, service: auth}\n"
            "detection: {sel: {program: CRON}, condition: sel}\n",
            encoding="utf-8",
        )
    return folder


def test_rejected_rules_are_reported(logs, tmp_path, capsys):
    rules = _rules_folder(tmp_path, valid=True)
    assert main(["analyze", str(logs), "-o", str(tmp_path / "out"), "--rules", str(rules)]) == 0
    captured = capsys.readouterr()
    assert "warning: rule rejected:" in captured.err
    assert "1 rules loaded" in captured.out


def test_no_valid_rule_is_an_error(logs, tmp_path, capsys):
    rules = _rules_folder(tmp_path, valid=False)
    out = tmp_path / "out"
    assert main(["analyze", str(logs), "-o", str(out), "--rules", str(rules)]) == 2
    err = capsys.readouterr().err
    assert "warning: rule rejected:" in err
    assert "no valid rule loaded" in err
    assert not out.exists()


def test_missing_rules_path_is_an_error(logs, tmp_path, capsys):
    argv = ["analyze", str(logs), "-o", str(tmp_path / "out"), "--rules", str(tmp_path / "nope")]
    assert main(argv) == 2
    assert "no such rule file or directory" in capsys.readouterr().err


def test_output_must_not_be_a_file(logs, tmp_path, capsys):
    target = tmp_path / "report.html"
    target.write_text("keep me", encoding="utf-8")
    assert main(["analyze", str(logs), "-o", str(target)]) == 2
    assert "--output must be a folder" in capsys.readouterr().err
    assert target.read_text(encoding="utf-8") == "keep me"


def test_timeline_limit(logs, tmp_path, capsys):
    out = tmp_path / "out"
    argv = ["analyze", str(logs), "-o", str(out), "--format", "json", "--full-timeline"]
    assert main([*argv, "--timeline-limit", "3"]) == 0
    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert len(data["timeline"]) == 3
    assert data["timeline_omitted"] == 138
    assert "Timeline: 138 event(s) beyond the first 3 left out" in capsys.readouterr().out


def test_empty_folder_warns(tmp_path, capsys):
    (tmp_path / "empty").mkdir()
    assert main(["analyze", str(tmp_path / "empty"), "-o", str(tmp_path / "out")]) == 0
    assert "no supported log file found" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (["--format", "pdf"], "--format expects html, md or json"),
        (["--format", ","], "--format expects html, md or json"),
        (["--tz", "Mars/Olympus"], "unknown time zone"),
        (["--year", "0"], "--year expects a year from 1 to 9999"),
        (["--year", "10000"], "--year expects a year from 1 to 9999"),
        (["--timeline-limit", "0"], "--timeline-limit expects a positive number"),
    ],
)
def test_usage_errors(logs, tmp_path, capsys, extra, message):
    assert main(["analyze", str(logs), "-o", str(tmp_path / "out"), *extra]) == 2
    assert message in capsys.readouterr().err


def test_missing_logs(tmp_path, capsys):
    assert main(["analyze", str(tmp_path / "nope")]) == 2
    assert "no such file or directory" in capsys.readouterr().err


def test_rules_command(capsys):
    assert main(["rules"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 53
    assert lines[0].startswith("high")
    assert any("SSH Failed Password (feeds a correlation)" in line for line in lines)
    assert any("[T1003.001]" in line for line in lines)


def test_version(capsys):
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"vigie {__version__}"


def test_broken_pipe_is_quiet(monkeypatch):
    """`vigie rules | head` must not end with a traceback."""
    import vigie.cli as cli

    def broken(_args):
        raise BrokenPipeError

    redirected = []
    monkeypatch.setattr(cli, "_list_rules", broken)
    monkeypatch.setattr(cli.os, "dup2", lambda *args: redirected.append(args))
    assert main(["rules"]) == 1
    assert len(redirected) == 1


def test_rules_command_reports_rejected_rules(tmp_path, capsys):
    assert main(["rules", "--rules", str(_rules_folder(tmp_path, valid=True))]) == 0
    captured = capsys.readouterr()
    assert captured.out.splitlines() == ["low           Any Cron Session  []"]
    assert "warning: rule rejected:" in captured.err


def test_rules_command_without_valid_rule(tmp_path, capsys):
    assert main(["rules", "--rules", str(_rules_folder(tmp_path, valid=False))]) == 2
    assert "no valid rule loaded" in capsys.readouterr().err


# --- Friendlier command line ---------------------------------------------------------


class TTY(io.StringIO):
    """Standard output that says it is a terminal."""

    encoding = "utf-8"

    def isatty(self):
        return True


def use_terminal(monkeypatch):
    """Make stdout a terminal (inside the test: pytest resets sys.stdout after setup)."""
    out = TTY()
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("TERM", raising=False)
    monkeypatch.setattr("vigie.term.time.sleep", lambda _seconds: None)
    # On Windows, stands for a console where escape sequences could be turned on.
    monkeypatch.setattr("vigie.term.enable_windows_vt", lambda _stream: True)
    return out


@pytest.fixture
def browser(monkeypatch):
    opened = []
    monkeypatch.setattr(cli.webbrowser, "open", lambda url: opened.append(url) or True)
    return opened


def test_terminal_gets_a_summary_box(logs, tmp_path, monkeypatch):
    terminal = use_terminal(monkeypatch)
    out = tmp_path / "out"
    assert main(["analyze", str(logs), "-o", str(out), "--year", "2024"]) == 0
    printed = terminal.getvalue()
    assert "\033[" in printed and "Summary" in printed and "Top alerts" in printed
    assert "SSH Login After Brute Force" in printed
    # The report paths come last, after a tip about --open.
    lines = printed.rstrip("\n").splitlines()
    assert "--open" in lines[-2]
    assert lines[-1].endswith(f"{out / 'report.html'}, {out / 'report.md'}")


@pytest.mark.parametrize("how", ["NO_COLOR", "--plain"])
def test_no_color_and_plain_print_what_a_pipe_gets(logs, tmp_path, monkeypatch, how):
    terminal = use_terminal(monkeypatch)
    piped = io.StringIO()
    monkeypatch.setattr(sys, "stdout", piped)
    assert main(["analyze", str(logs), "-o", str(tmp_path / "a"), "--year", "2024"]) == 0
    monkeypatch.setattr(sys, "stdout", terminal)
    argv = ["analyze", str(logs), "-o", str(tmp_path / "a"), "--year", "2024"]
    if how == "NO_COLOR":
        monkeypatch.setenv("NO_COLOR", "1")
    else:
        argv.append("--plain")
    assert main(argv) == 0
    assert terminal.getvalue() == piped.getvalue()
    assert "\033" not in terminal.getvalue()


def test_open_shows_the_report_in_the_browser(logs, tmp_path, capsys, browser):
    out = tmp_path / "out"
    assert main(["analyze", str(logs), "-o", str(out), "--open"]) == 0
    assert browser == [(out / "report.html").resolve().as_uri()]
    lines = capsys.readouterr().out.splitlines()
    assert lines[-2] == "Opening the report in your browser."
    assert lines[-1].startswith("Report: ")


def test_open_without_a_browser_warns(logs, tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(cli.webbrowser, "open", lambda url: False)
    assert main(["analyze", str(logs), "-o", str(tmp_path / "out"), "--open"]) == 0
    assert "could not open a browser" in capsys.readouterr().err


def test_open_needs_the_html_report(logs, tmp_path, capsys, browser):
    assert main(["analyze", str(logs), "-o", str(tmp_path), "--format", "json", "--open"]) == 2
    assert "--open opens the HTML report" in capsys.readouterr().err
    assert browser == []


def test_demo_writes_and_opens_a_report(tmp_path, capsys, browser):
    out = tmp_path / "demo"
    assert main(["demo", "-o", str(out)]) == 0
    html = (out / "report.html").read_text(encoding="utf-8")
    assert "LLM Prompt Injection In Retrieved Content Or Tool Result" in html
    assert "Poisoned MCP Tool Description" in html
    assert "SSH Login After Brute Force" in html
    assert sorted(p.name for p in out.iterdir()) == ["report.html"]
    assert browser == [(out / "report.html").resolve().as_uri()]
    printed = capsys.readouterr().out
    assert printed.startswith("Analyzing the sample logs shipped with Vigie")
    assert "Read 90 events from 9 file(s)" in printed


def test_demo_no_open(tmp_path, capsys, browser):
    out = tmp_path / "demo"
    assert main(["demo", "--no-open", "-o", str(out)]) == 0
    assert (out / "report.html").is_file()
    assert browser == []
    assert capsys.readouterr().out.splitlines()[-1] == f"Report: {out / 'report.html'}"


def test_demo_defaults_to_a_new_temporary_folder(capsys, browser, monkeypatch, tmp_path):
    monkeypatch.setattr(cli.tempfile, "tempdir", str(tmp_path))
    assert main(["demo", "--no-open"]) == 0
    (folder,) = tmp_path.glob("vigie-demo-*")
    assert (folder / "report.html").is_file()


def test_demo_prints_the_real_path_of_its_temporary_folder(capsys, browser, monkeypatch, tmp_path):
    # A link stands in for a Windows short 8.3 name of %TEMP%: another name for
    # the same folder, which only resolve() turns into the real one.
    real = tmp_path / "a-long-folder-name"
    real.mkdir()
    alias = tmp_path / "ALONGF~1"
    try:
        alias.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("this account cannot create symbolic links")
    monkeypatch.setattr(cli.tempfile, "tempdir", str(alias))
    assert main(["demo", "--no-open"]) == 0
    (folder,) = real.glob("vigie-demo-*")
    last = capsys.readouterr().out.splitlines()[-1]
    assert last == f"Report: {folder.resolve() / 'report.html'}"
    assert "ALONGF~1" not in last


def test_demo_samples_are_copies_of_the_fixtures():
    from vigie.demo import DEMO_LOGS

    names = sorted(path.name for path in DEMO_LOGS.iterdir())
    assert "auth.log" in names and len(names) == 9
    for path in DEMO_LOGS.iterdir():
        folder = "authlog" if path.name == "auth.log" else "agentlog"
        assert path.read_bytes() == (FIXTURES / folder / path.name).read_bytes(), path.name


def test_errors_say_what_to_try(tmp_path, capsys):
    assert main(["analyze", str(tmp_path / "nope")]) == 2
    err = capsys.readouterr().err
    assert err.splitlines()[0] == f"vigie: error: no such file or directory: {tmp_path / 'nope'}"
    assert err.splitlines()[1].startswith("hint: ") and "vigie demo" in err
    (tmp_path / "empty").mkdir()
    assert main(["analyze", str(tmp_path / "empty"), "-o", str(tmp_path / "out")]) == 0
    err = capsys.readouterr().err
    assert "no supported log file found" in err and ".evtx" in err and "vigie demo" in err


def test_no_command_prints_help_with_examples(capsys):
    assert main([]) == 2
    printed = capsys.readouterr().out
    assert "vigie demo" in printed and "vigie analyze ./logs --open" in printed
