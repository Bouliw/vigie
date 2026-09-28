import json
import os
import shutil
from pathlib import Path

import pytest

from vigie import __version__
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
        "Read 141 events from 2 file(s), 1 parser warning(s) listed in the report. 23 rules loaded."
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


def test_time_zone_shifts_classic_syslog(logs, tmp_path):
    out = tmp_path / "out"
    argv = ["analyze", str(logs), "-o", str(out), "--format", "json", "--year", "2024"]
    assert main([*argv, "--tz", "Europe/Berlin"]) == 0
    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    (chain,) = [a for a in data["alerts"] if a["rule"]["title"] == "SSH Login After Brute Force"]
    assert chain["first_seen"] == "2024-03-10T08:05:42Z"  # 09:05:42 in Berlin (UTC+1)


def test_undecodable_text_does_not_break_the_report(tmp_path):
    folder = tmp_path / "logs"
    folder.mkdir()
    # A file name that is not valid UTF-8 decodes to a lone surrogate (PEP 383).
    name = os.fsdecode(b"auth-\xff.log")
    shutil.copy(FIXTURES / "authlog" / "auth.log", folder / name)
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
    assert len(lines) == 23
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
