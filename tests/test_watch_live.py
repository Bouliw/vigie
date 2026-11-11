"""``vigie watch`` on the live logs of Linux (systemd journal) and Windows (event log),
and desktop notifications on every system."""

import base64
import io
import json
import re
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from evtx import PyEvtxParser

import vigie.cli as cli
import vigie.watch as watch
from vigie.cli import main
from vigie.collect import collect
from vigie.rules import RULES_DIR
from vigie.sigma.engine import Engine
from vigie.sigma.loader import load_rules
from vigie.timeutils import UTC
from vigie.watch import (
    JournaldSource,
    Watcher,
    WatchError,
    WindowsChannelError,
    WindowsEventSource,
    windows_sources,
)

FIXTURES = Path(__file__).parent / "fixtures"
NOW = datetime(2024, 3, 11, tzinfo=UTC)
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


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


def drain(source, polls=500):
    """Poll a command source until its command ends; return what it read."""
    events = []
    with pytest.raises(WatchError, match=r"stopped \(exit code 0\)"):
        for _ in range(polls):
            events += source.poll(NOW)
            watch.time.sleep(0.01)
    source.close()
    return events


# --- Linux: the systemd journal -------------------------------------------------------


def journal_of(path):
    """The entries journalctl would print for the events of an auth.log."""
    lines = []
    for event in collect(path).events:
        micros = (event.timestamp - EPOCH) // timedelta(microseconds=1)
        entry = {
            "__REALTIME_TIMESTAMP": str(micros),
            "_HOSTNAME": event.host,
            "SYSLOG_IDENTIFIER": event.get("program"),
            "MESSAGE": event.get("message"),
        }
        if event.get("pid"):
            entry["_PID"] = event.get("pid")
        lines.append(json.dumps(entry))
    return "\n".join(lines) + "\n"


def printing(tmp_path, text):
    """A command that prints ``text`` then exits, standing for journalctl."""
    path = tmp_path / "output.txt"
    path.write_text(text, encoding="utf-8")
    return [sys.executable, "-c", f"print(open({str(path)!r}).read(), end='')"]


def test_journalctl_reads_new_entries_of_auth_programs_only(monkeypatch):
    commands = []

    class Process:
        stdout = io.StringIO("")

        def __init__(self, command, **_options):
            commands.append(command)

        def poll(self):
            return 0

    monkeypatch.setattr(watch.subprocess, "Popen", Process)
    JournaldSource().close()
    (command,) = commands
    assert command[:5] == ["journalctl", "--follow", "--lines=0", "--output=json", "--no-pager"]
    assert "SYSLOG_IDENTIFIER=sshd-session" in command
    assert "SYSLOG_IDENTIFIER=sudo" in command
    assert all(arg.startswith(("--", "SYSLOG_IDENTIFIER=")) for arg in command[1:])


def test_journald_source_raises_the_alerts_of_analyze(tmp_path):
    fixture = FIXTURES / "authlog" / "auth.log"
    source = JournaldSource(command=printing(tmp_path, journal_of(fixture)))
    watcher, notes = make_watcher(tmp_path, [source])
    with pytest.raises(WatchError, match=r"journalctl stopped \(exit code 0\)"):
        for _ in range(500):
            watcher.step()
            watch.time.sleep(0.01)
    source.close()

    def key(alert):
        return alert.rule.id, len(alert.events)

    batch = Engine(load_rules(RULES_DIR)).evaluate(collect(fixture).events)
    assert sorted(map(key, watcher.alerts)) == sorted(map(key, batch.alerts))
    assert source.report.events == len(collect(fixture).events)
    assert notes == [
        ("Vigie: high alert", "SSH Login After Brute Force: src_ip=203.0.113.45 (11 events)")
    ]
    assert all(event.origin.startswith("journald:") for a in watcher.alerts for event in a.events)


def test_journald_source_reports_why_journalctl_failed():
    command = [sys.executable, "-c", "import sys; sys.exit('No journal files were found.')"]
    source = JournaldSource(command=command)
    with pytest.raises(WatchError, match=r"journalctl stopped \(exit code 1\).*No journal"):
        for _ in range(500):
            source.poll(NOW)
            watch.time.sleep(0.01)
    source.close()


@pytest.mark.skipif(not hasattr(watch.os, "geteuid"), reason="POSIX only")
def test_journal_access_hint(monkeypatch):
    monkeypatch.setattr(watch.os, "geteuid", lambda: 0)
    assert watch.journal_access_hint() is None
    monkeypatch.setattr(watch.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(watch.os, "getgroups", lambda: [1000, 4])
    import grp

    names = {1000: "alice", 4: "adm"}
    monkeypatch.setattr(grp, "getgrgid", lambda gid: type("G", (), {"gr_name": names[gid]}))
    assert watch.journal_access_hint() is None
    names[4] = "users"
    assert "systemd-journal" in watch.journal_access_hint()


# --- Windows: the event log, through wevtutil ---------------------------------------


def xml_records(name):
    path = FIXTURES / "evtx" / name
    return [record["data"].split("?>", 1)[1] for record in PyEvtxParser(str(path)).records()]


def renumbered(record, number):
    tag = f"<EventRecordID>{number}</EventRecordID>"
    return re.sub(r"<EventRecordID>\d+</EventRecordID>", tag, record)


class FakeChannel:
    """Stands for wevtutil on one channel: answers its queries from a list of records."""

    def __init__(self, records=(), *, utf16=True):
        self.records = list(records)
        self.utf16 = utf16
        self.commands = []

    def add(self, *records):
        start = len(self.records) + 1
        self.records += [renumbered(r, start + i) for i, r in enumerate(records)]

    def clear(self, *records):
        self.records = []
        self.add(*records)

    def __call__(self, command):
        self.commands.append(command)
        assert command[:2] == ["wevtutil", "qe"]
        assert command[-3:] == ["/f:xml", "/e:Events", "/uni:true"]
        options = dict(option[1:].split(":", 1) for option in command[3:-3])
        records = self.records
        if "q" in options:
            after = int(re.search(r"EventRecordID>(\d+)", options["q"])[1])
            records = [r for r in records if int(re.search(r"ID>(\d+)<", r)[1]) > after]
        if options.get("rd") == "true":
            records = records[::-1]
        if "c" in options:
            records = records[: int(options["c"])]
        text = "<Events>" + "".join(records) + "</Events>"
        data = b"\xff\xfe" + text.encode("utf-16-le") if self.utf16 else text.encode()
        return subprocess.CompletedProcess(command, 0, data, b"")


def failing(code, message):
    def run(command):
        return subprocess.CompletedProcess(command, code, b"", message.encode())

    return run


SECURITY = xml_records("DE_1102_security_log_cleared.evtx")


def test_windows_source_starts_at_the_end_and_reads_new_records_in_order():
    channel = FakeChannel()
    channel.add(*SECURITY[:5])
    source = WindowsEventSource("Security", runner=channel)
    assert source.poll(NOW) == []
    channel.add(*SECURITY[5:8])
    events = source.poll(NOW)
    assert [event.origin for event in events] == ["Security#6", "Security#7", "Security#8"]
    assert source.poll(NOW) == []
    assert source.report.events == 3
    assert source.report.format == "evtx"


def test_windows_source_reads_everything_after_a_burst():
    channel = FakeChannel(utf16=False)
    source = WindowsEventSource("Security", runner=channel)  # an empty log
    burst = (SECURITY * 3)[: watch.WINDOWS_PAGE + 10]
    channel.add(*burst)
    events = source.poll(NOW)
    assert [event.origin for event in events] == [f"Security#{n}" for n in range(1, len(burst) + 1)]
    assert any(option.startswith("/q:") for option in channel.commands[-1])


def test_windows_source_reads_a_cleared_log_from_its_first_record():
    channel = FakeChannel()
    channel.add(*SECURITY[:20])
    source = WindowsEventSource("Security", runner=channel)
    log_cleared = next(r for r in SECURITY if "<EventID>1102<" in r)
    channel.clear(log_cleared, SECURITY[1])  # numbering starts over at 1
    events = source.poll(NOW)
    assert (events[0].event_id, events[0].origin) == (1102, "Security#1")
    assert len(events) == 2


def test_watcher_alerts_on_a_cleared_security_log(tmp_path):
    channel = FakeChannel()
    channel.add(*SECURITY[:3])
    watcher, _ = make_watcher(tmp_path, [WindowsEventSource("Security", runner=channel)])
    channel.clear(next(r for r in SECURITY if "<EventID>1102<" in r))
    fired = watcher.step()
    assert [alert.rule.title for alert in fired] == ["Security Event Log Cleared"]
    assert "HIGH" in watcher.out.getvalue()


def test_windows_security_log_needs_an_administrator():
    runner = failing(5, "Failed to read events. Access is denied.")
    with pytest.raises(WindowsChannelError, match="needs an administrator"):
        WindowsEventSource("Security", runner=runner)
    with pytest.raises(WindowsChannelError, match="needs an administrator"):
        windows_sources(["Security"], runner=runner)


def test_missing_channels_are_left_out():
    def runner(command):
        if "Microsoft-Windows-Sysmon/Operational" in command:
            return failing(15007, "The specified channel could not be found.")(command)
        return FakeChannel()(command)

    sources, notes = windows_sources(runner=runner)
    assert [source.channel for source in sources] == ["Security", "System"]
    assert notes == [
        "Microsoft-Windows-Sysmon/Operational left out: cannot read the "
        "Microsoft-Windows-Sysmon/Operational log: The specified channel could not be found."
    ]


def test_unreadable_output_is_a_warning():
    def runner(command):
        return subprocess.CompletedProcess(command, 0, b"<Events><Event>", b"")

    source = WindowsEventSource("System", runner=runner)
    assert source.poll(NOW) == []
    assert source.report.warnings[-1].startswith("System: unreadable wevtutil output")


def test_decode_output():
    assert watch.decode_output("é".encode("utf-16")) == "é"
    assert watch.decode_output("<a>é</a>".encode()) == "<a>é</a>"
    assert watch.decode_output(b"\xe9") in ("é", "\xe9")


# --- Desktop notifications ------------------------------------------------------------


def test_desktop_notifier_per_system(monkeypatch):
    monkeypatch.setattr(watch.Path, "exists", lambda self: True)
    assert watch.desktop_notifier("darwin") is watch.notify
    assert watch.desktop_notifier("win32") is watch.notify_windows
    monkeypatch.setattr(watch.shutil, "which", lambda name: f"/usr/bin/{name}")
    assert watch.desktop_notifier("linux") is watch.notify_linux
    monkeypatch.setattr(watch.shutil, "which", lambda name: None)
    assert watch.desktop_notifier("linux") is None


def test_linux_notification_shows_the_message_as_text(monkeypatch):
    calls = []
    monkeypatch.setattr(watch, "_in_background", lambda command, env=None: calls.append(command))
    watch.notify_linux("Vigie: high alert", "-x <b>root</b> & co")
    assert calls == [
        [
            "notify-send",
            "--app-name=Vigie",
            "--",
            "Vigie: high alert",
            "-x &lt;b&gt;root&lt;/b&gt; &amp; co",
        ]
    ]


def test_windows_notification_passes_the_texts_as_data(monkeypatch):
    calls = []
    monkeypatch.setattr(
        watch, "_in_background", lambda command, env=None: calls.append((command, env))
    )
    message = "'; Remove-Item C:\\ -Recurse; '$(calc)"
    watch.notify_windows("Vigie: high alert", message)
    ((command, env),) = calls
    assert command[0].endswith("powershell.exe")
    script = base64.b64decode(command[-1]).decode("utf-16-le")
    assert script == watch.WINDOWS_TOAST_SCRIPT
    assert message not in " ".join(command)
    assert env["VIGIE_NOTIFY_TITLE"] == "Vigie: high alert"
    assert env["VIGIE_NOTIFY_MESSAGE"] == message


def test_a_notification_command_that_fails_is_ignored():
    watch._in_background(["/nonexistent/notify-send", "title"])  # no exception, no wait


# --- The command line ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("platform", "extra", "message"),
    [
        ("darwin", ["--journald"], "it needs Linux with journalctl"),
        ("linux", ["--windows"], "it needs Windows"),
        ("win32", ["--channel", "System", "missing.log"], "add --windows"),
    ],
)
def test_live_options_need_their_system(monkeypatch, capsys, platform, extra, message):
    monkeypatch.setattr(sys, "platform", platform)
    monkeypatch.setattr(cli.shutil, "which", lambda name: None)
    assert main(["watch", *extra]) == 2
    assert message in capsys.readouterr().err


def test_watch_journald_command(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(cli.shutil, "which", lambda name: f"/usr/bin/{name}")
    command = printing(tmp_path, journal_of(FIXTURES / "authlog" / "auth.log"))
    monkeypatch.setattr(cli, "JournaldSource", lambda: JournaldSource(command=command))
    monkeypatch.setattr(cli, "journal_access_hint", lambda: "run vigie with sudo")
    monkeypatch.setattr(cli, "desktop_notifier", lambda: None)
    monkeypatch.setattr(watch.time, "sleep", lambda seconds: watch.time.monotonic())
    out = tmp_path / "out"
    assert main(["watch", "--journald", "-o", str(out), "--plain"]) == 1
    captured = capsys.readouterr()
    assert "Watching the systemd journal with 53 rules." in captured.out
    assert "note: run vigie with sudo" in captured.err
    assert "note: no desktop notifications: notify-send is missing" in captured.err
    assert "SSH Login After Brute Force" in captured.out
    assert (out / "report.html").is_file()


def test_watch_windows_command(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(cli.shutil, "which", lambda name: f"C:\\Windows\\System32\\{name}.exe")
    channel = FakeChannel()
    channel.add(*SECURITY[:2])

    def sources(channels):
        assert list(channels) == ["Security", "Microsoft-Windows-PowerShell/Operational"]
        return windows_sources(channels[:1], runner=channel)[0], ["PowerShell left out"]

    monkeypatch.setattr(cli, "windows_sources", sources)
    notes = []
    monkeypatch.setattr(cli, "desktop_notifier", lambda: lambda *texts: notes.append(texts))

    sleeps = []

    def stop(_seconds):
        sleeps.append(_seconds)
        if len(sleeps) == 1:
            channel.add(next(r for r in SECURITY if "<EventID>1102<" in r))
        else:
            raise KeyboardInterrupt

    monkeypatch.setattr(watch.time, "sleep", stop)
    out = tmp_path / "out"
    argv = ["watch", "--windows", "--channel", "Security"]
    argv += ["--channel", "Microsoft-Windows-PowerShell/Operational", "-o", str(out), "--plain"]
    assert main(argv) == 0
    captured = capsys.readouterr()
    assert "Watching the Windows Security log with 53 rules." in captured.out
    assert "high and above also raise a notification" in captured.out
    assert "note: PowerShell left out" in captured.err
    alert = "HIGH          Security Event Log Cleared  [T1685.005]  SubjectUserName=user01"
    assert alert in captured.out
    assert notes == [("Vigie: high alert", notes[0][1])]
    assert "Security Event Log Cleared" in notes[0][1]


def test_watch_windows_without_administrator(monkeypatch, capsys):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(cli.shutil, "which", lambda name: name)

    def denied(channels):
        raise WindowsChannelError("reading the Security log needs an administrator: ...")

    monkeypatch.setattr(cli, "windows_sources", denied)
    assert main(["watch", "--windows"]) == 2
    assert "needs an administrator" in capsys.readouterr().err


@pytest.mark.skipif(
    sys.platform != "win32" or not watch.shutil.which("wevtutil"), reason="needs Windows"
)
def test_real_windows_system_log():
    # The System log is readable without administrator rights.
    source = WindowsEventSource("System")
    assert source._last > 0
    for event in source.poll(datetime.now(UTC)):
        assert event.origin.startswith("System#")
        assert event.get("Channel") == "System"
    newest = source._query(["/c:1", "/rd:true"])
    event = watch.winxml.build_event(newest[0], "System")
    assert event.source == "system"
    assert event.event_id > 0
