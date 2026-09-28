import pytest

from vigie.sigma.logsource import resolve_logsource
from vigie.sigma.matcher import SigmaError


def test_windows_service(make_event):
    (target,) = resolve_logsource({"product": "windows", "service": "Security"})
    assert target.source == "security"
    assert target.accepts(make_event("security", event_id=4625))
    assert not target.accepts(make_event("system", event_id=7045))


def test_process_creation_covers_sysmon_and_4688(make_event):
    sysmon, security = resolve_logsource({"product": "windows", "category": "process_creation"})
    assert sysmon.accepts(make_event("sysmon", event_id=1))
    assert not sysmon.accepts(make_event("sysmon", event_id=3))
    assert security.accepts(make_event("security", event_id=4688))
    # Sigma uses Sysmon names; 4688 stores the same data under other names.
    assert security.field_name("Image") == "NewProcessName"
    assert security.field_name("ParentImage") == "ParentProcessName"
    assert security.field_name("CommandLine") == "CommandLine"
    assert sysmon.field_name("Image") == "Image"


def test_sysmon_category(make_event):
    (target,) = resolve_logsource({"product": "windows", "category": "process_access"})
    assert target.accepts(make_event("sysmon", event_id=10))


def test_linux_services(make_event):
    (auth,) = resolve_logsource({"product": "linux", "service": "auth"})
    assert auth.accepts(make_event("auth", program="CRON"))

    (sshd,) = resolve_logsource({"product": "linux", "service": "sshd"})
    assert sshd.accepts(make_event("auth", program="sshd"))
    assert not sshd.accepts(make_event("auth", program="sudo"))
    assert not sshd.accepts(make_event("sysmon", event_id=1))


def test_definition_is_ignored():
    logsource = {"product": "windows", "service": "sysmon", "definition": "Requires Sysmon"}
    assert resolve_logsource(logsource)[0].source == "sysmon"


@pytest.mark.parametrize(
    "logsource",
    [
        {"product": "windows", "service": "dns-server"},
        {"product": "windows", "category": "antivirus"},
        {"product": "linux", "category": "process_creation"},
        {"product": "linux", "service": "auditd"},
        {"product": "macos", "category": "process_creation"},
        {"category": "firewall"},
        {},
    ],
)
def test_unsupported(logsource):
    with pytest.raises(SigmaError, match="unsupported logsource"):
        resolve_logsource(logsource)


def test_not_a_mapping():
    with pytest.raises(SigmaError, match="must be a mapping"):
        resolve_logsource("windows")
