import io
import shutil
import sys
from datetime import datetime
from pathlib import Path

import pytest

import vigie.watch as watch
from vigie.cli import main
from vigie.collect import collect
from vigie.parsers import unifiedlog
from vigie.rules import RULES_DIR
from vigie.sigma.engine import Engine
from vigie.sigma.loader import load_rules
from vigie.timeutils import UTC
from vigie.watch import FileSource, UnifiedLogSource, Watcher, WatchError

FIXTURES = Path(__file__).parent / "fixtures"
NOW = datetime(2024, 3, 11, tzinfo=UTC)  # the day after the synthetic auth.log
LINE = (
    "Mar 10 09:00:{:02d} web01 sshd[100]: "
    "Failed password for root from 203.0.113.9 port 4{:04d} ssh2\n"
)


def append(path, text):
    with path.open("a", encoding="utf-8") as handle:
        handle.write(text)


@pytest.fixture
def auth_log(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text(LINE.format(0, 0) * 3, encoding="utf-8")
    return path


def test_file_source_reads_new_lines_only(auth_log):
    source = FileSource(auth_log, "authlog")
    assert source.poll(NOW) == []
    append(auth_log, LINE.format(1, 1) + LINE.format(2, 2))
    events = source.poll(NOW)
    assert [event.origin for event in events] == ["auth.log:4", "auth.log:5"]
    assert events[0].get("src_ip") == "203.0.113.9"
    assert source.report.events == 2


def test_file_source_waits_for_the_end_of_a_line(auth_log):
    source = FileSource(auth_log, "authlog")
    line = LINE.format(3, 3)
    append(auth_log, line[:30])
    assert source.poll(NOW) == []
    append(auth_log, line[30:])
    assert len(source.poll(NOW)) == 1


def test_file_source_follows_rotation(auth_log):
    source = FileSource(auth_log, "authlog")
    append(auth_log, LINE.format(4, 4))
    auth_log.rename(auth_log.with_name("auth.log.1"))
    assert len(source.poll(NOW)) == 1  # the last line of the rotated file
    auth_log.write_text(LINE.format(5, 5), encoding="utf-8")
    (event,) = source.poll(NOW)
    assert event.origin == "auth.log:1"


def test_file_source_follows_truncation(auth_log):
    source = FileSource(auth_log, "authlog")
    auth_log.write_text("", encoding="utf-8")
    assert source.poll(NOW) == []
    append(auth_log, LINE.format(6, 6))
    (event,) = source.poll(NOW)
    assert event.origin == "auth.log:1"


def test_classic_syslog_year_around_new_year(auth_log):
    source = FileSource(auth_log, "authlog")
    append(auth_log, "Dec 31 23:59:58 web01 sudo: pam_unix(sudo:session): session closed\n")
    (event,) = source.poll(datetime(2025, 1, 1, 0, 0, 5, tzinfo=UTC))
    assert event.timestamp.year == 2024


def test_file_source_reads_unified_log_exports(tmp_path):
    path = tmp_path / "live.ndjson"
    path.write_text("", encoding="utf-8")
    source = FileSource(path, "unifiedlog")
    fixture = FIXTURES / "unifiedlog" / "mac_sudo.ndjson"
    append(path, fixture.read_text(encoding="utf-8"))
    assert len(source.poll(NOW)) == len(unifiedlog.parse(fixture).events)


def test_unified_log_source_reads_log_stream_output():
    fixture = FIXTURES / "unifiedlog" / "mac_ssh.ndjson"
    command = [sys.executable, "-c", f"print(open({str(fixture)!r}).read(), end='')"]
    source = UnifiedLogSource(command=command)
    events = []
    with pytest.raises(WatchError, match=r"log stream stopped \(exit code 0\)"):
        for _ in range(500):
            events += source.poll(NOW)
            watch.time.sleep(0.01)
    source.close()
    assert len(events) == len(unifiedlog.parse(fixture).events) == 14
    assert events[0].origin == "log stream:2"  # line 1 is the "Filtering the log data" header


def test_unified_log_source_reports_why_log_stream_failed():
    command = [sys.executable, "-c", "import sys; sys.exit('log: Must be admin to run this')"]
    source = UnifiedLogSource(command=command)
    with pytest.raises(WatchError, match=r"exit code 1.*Must be admin"):
        for _ in range(500):
            source.poll(NOW)
            watch.time.sleep(0.01)
    source.close()


def make_watcher(tmp_path, sources, **options):
    notes = []
    watcher = Watcher(
        sources,
        load_rules(RULES_DIR),
        tmp_path / "out" / "report.html",
        out=io.StringIO(),
        notifier=lambda title, message: notes.append((title, message)),
        clock=lambda: NOW,
        **options,
    )
    return watcher, notes


def test_watcher_raises_the_alerts_of_analyze(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text("", encoding="utf-8")
    watcher, notes = make_watcher(tmp_path, [FileSource(path, "authlog")])
    shutil.copyfileobj((FIXTURES / "authlog" / "auth.log").open(), path.open("a"))
    fired = watcher.step()

    def key(alert):
        return alert.rule.id, tuple(event.origin for event in alert.events)

    batch = Engine(load_rules(RULES_DIR)).evaluate(
        collect(FIXTURES / "authlog" / "auth.log").events
    )
    assert sorted(map(key, fired)) == sorted(map(key, batch.alerts))
    printed = watcher.out.getvalue().splitlines()
    assert len(printed) == 5  # 1 high, 3 medium, 1 low; the informational ones are hidden
    # A correlation is printed when it completes, with its group and size.
    assert (
        "2024-03-10 09:07:05Z  HIGH          SSH Login After Brute Force  [T1078.003, T1110.001]  "
        "src_ip=203.0.113.45 (11 events)"
    ) in printed
    assert notes == [
        ("Vigie: high alert", "SSH Login After Brute Force: src_ip=203.0.113.45 (11 events)")
    ]


def test_notifications_of_a_rule_wait_a_minute(tmp_path, auth_log):
    watcher, notes = make_watcher(tmp_path, [FileSource(auth_log, "authlog")], notify_level="low")
    append(auth_log, "".join(LINE.format(10 + i, i) for i in range(25)))
    watcher.step()
    # 25 failures make 2 brute force alerts: one notification.
    assert [title for title, _ in notes] == ["Vigie: medium alert"]


def test_notifications_off(tmp_path, auth_log):
    watcher, notes = make_watcher(tmp_path, [FileSource(auth_log, "authlog")], notify_level=None)
    append(auth_log, "".join(LINE.format(10 + i, i) for i in range(10)))
    assert len(watcher.step()) == 1
    assert notes == []


def test_live_and_final_report(tmp_path, auth_log):
    watcher, _ = make_watcher(tmp_path, [FileSource(auth_log, "authlog")], refresh=7)
    append(auth_log, "".join(LINE.format(10 + i, i) for i in range(10)))
    watcher.step()
    watcher.update_report()
    html = watcher.report_path.read_text(encoding="utf-8")
    assert '<meta http-equiv="refresh" content="7">' in html
    assert "<strong>Live</strong>" in html
    assert "SSH Brute Force" in html
    assert '10</div><div class="label">events analyzed' in html
    watcher.write_report(live=False)
    html = watcher.report_path.read_text(encoding="utf-8")
    assert "http-equiv" not in html
    assert "ran from 2024-03-11 00:00:00Z to 2024-03-11 00:00:00Z" in html
    assert not list(watcher.report_path.parent.glob(".*.tmp"))


class Interrupting:
    """A source that stops the watch on its second poll, as Ctrl-C would."""

    def __init__(self):
        self.report = watch.FileReport("test", "authlog", 0)
        self.polls = 0
        self.closed = False

    def poll(self, now):
        self.polls += 1
        if self.polls == 2:
            raise KeyboardInterrupt
        return []

    def close(self):
        self.closed = True


def test_run_writes_the_final_report_on_ctrl_c(tmp_path):
    source = Interrupting()
    watcher, _ = make_watcher(tmp_path, [source])
    watcher.run(interval=0)
    assert source.closed
    assert "http-equiv" not in watcher.report_path.read_text(encoding="utf-8")


# --- Command line --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        ([], "nothing to watch"),
        (["missing.log"], "no such file"),
        (["--refresh", "0", "auth.log"], "--refresh expects a positive number"),
        (["evtx/DE_1102_security_log_cleared.evtx"], "vigie watch follows auth.log files"),
        (["authlog/auth.log.2.gz"], "vigie watch follows auth.log files"),
        (["--tz", "Mars/Olympus", "auth.log"], "unknown time zone"),
    ],
)
def test_watch_usage_errors(tmp_path, monkeypatch, capsys, extra, message):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "auth.log").write_text("", encoding="utf-8")
    shutil.copytree(FIXTURES / "evtx", tmp_path / "evtx")
    (tmp_path / "authlog").mkdir()
    (tmp_path / "authlog" / "auth.log.2.gz").write_bytes(b"")
    assert main(["watch", *extra]) == 2
    assert message in capsys.readouterr().err


def test_watch_macos_needs_macos(monkeypatch, capsys):
    monkeypatch.setattr(sys, "platform", "linux")
    assert main(["watch", "--macos"]) == 2
    assert "needs macOS" in capsys.readouterr().err


def test_watch_command(tmp_path, monkeypatch, capsys, auth_log):
    def stop(_seconds):
        append(auth_log, "".join(LINE.format(10 + i, i) for i in range(10)))
        raise KeyboardInterrupt

    monkeypatch.setattr(watch.time, "sleep", stop)
    out = tmp_path / "out"
    assert main(["watch", str(auth_log), "-o", str(out), "--notify-level", "off"]) == 0
    printed = capsys.readouterr().out
    assert f"Watching {auth_log} with 36 rules. Stop with Ctrl-C." in printed
    assert "Alerts at level low and above are printed." in printed
    assert f"Stopped. Read 0 events, alerts: none. Report: {out / 'report.html'}" in printed
    assert (out / "report.html").is_file()
