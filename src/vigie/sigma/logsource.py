"""Route Sigma rules to the events they apply to, based on their ``logsource``.

A Sigma rule does not say "read file X"; it declares the kind of log it is
written for, e.g. ``{product: windows, service: security}`` or
``{product: windows, category: process_creation}``. This module turns that
declaration into :class:`Target` filters on Vigie events.

A *category* is abstract: ``process_creation`` is Sysmon event 1 *or*
Security event 4688. The two do not use the same field names, so a target can
carry aliases that translate the Sigma (Sysmon-style) name into the name the
event actually uses, e.g. ``Image`` -> ``NewProcessName`` for 4688.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from vigie.models import Event
from vigie.sigma.matcher import SigmaError


@dataclass(frozen=True)
class Target:
    """One kind of event a rule applies to, with optional field-name aliases."""

    source: str
    event_ids: frozenset[int] | None = None
    programs: frozenset[str] | None = None
    aliases: Mapping[str, str] = field(default_factory=dict)

    def accepts(self, event: Event) -> bool:
        if event.source != self.source:
            return False
        if self.event_ids is not None and event.event_id not in self.event_ids:
            return False
        return self.programs is None or event.get("program") in self.programs

    def field_name(self, sigma_field: str) -> str:
        return self.aliases.get(sigma_field, sigma_field)


def _sysmon(*event_ids: int) -> Target:
    return Target("sysmon", frozenset(event_ids))


# Security 4688 names for the Sysmon-style fields used by process_creation rules.
_PROCESS_CREATION_4688 = MappingProxyType(
    {
        "Image": "NewProcessName",
        "ParentImage": "ParentProcessName",
        "User": "SubjectUserName",
    }
)

WINDOWS_SERVICES = frozenset(
    {
        "security",
        "system",
        "application",
        "sysmon",
        "powershell",
        "powershell-classic",
        "taskscheduler",
        "windefend",
    }
)

WINDOWS_CATEGORIES: Mapping[str, tuple[Target, ...]] = MappingProxyType(
    {
        "process_creation": (
            _sysmon(1),
            Target("security", frozenset({4688}), aliases=_PROCESS_CREATION_4688),
        ),
        "process_termination": (_sysmon(5),),
        "network_connection": (_sysmon(3),),
        "driver_load": (_sysmon(6),),
        "image_load": (_sysmon(7),),
        "create_remote_thread": (_sysmon(8),),
        "raw_access_thread": (_sysmon(9),),
        "process_access": (_sysmon(10),),
        "file_event": (_sysmon(11),),
        "registry_add": (_sysmon(12),),
        "registry_delete": (_sysmon(12),),
        "registry_set": (_sysmon(13),),
        "registry_rename": (_sysmon(14),),
        "registry_event": (_sysmon(12, 13, 14),),
        "create_stream_hash": (_sysmon(15),),
        "pipe_created": (_sysmon(17, 18),),
        "wmi_event": (_sysmon(19, 20, 21),),
        "dns_query": (_sysmon(22),),
        "file_delete": (_sysmon(23, 26),),
        "ps_module": (Target("powershell", frozenset({4103})),),
        "ps_script": (Target("powershell", frozenset({4104})),),
        "ps_classic_start": (Target("powershell-classic", frozenset({400})),),
    }
)

LINUX_SERVICES: Mapping[str, tuple[Target, ...]] = MappingProxyType(
    {
        "auth": (Target("auth"),),
        # OpenSSH 9.8+ logs per-connection messages as sshd-session, 10.0+ also sshd-auth.
        "sshd": (Target("auth", programs=frozenset({"sshd", "sshd-session", "sshd-auth"})),),
        "sudo": (Target("auth", programs=frozenset({"sudo"})),),
    }
)


def resolve_logsource(logsource: Any) -> tuple[Target, ...]:
    """Return the targets for a rule's ``logsource``, or raise SigmaError if unsupported."""
    if not isinstance(logsource, Mapping):
        raise SigmaError("logsource must be a mapping")
    product = str(logsource.get("product", "")).lower()
    service = str(logsource.get("service", "")).lower()
    category = str(logsource.get("category", "")).lower()
    description = ", ".join(f"{k}: {v}" for k, v in logsource.items() if k != "definition")

    if product == "windows":
        if category:
            if category in WINDOWS_CATEGORIES:
                return WINDOWS_CATEGORIES[category]
        elif service in WINDOWS_SERVICES:
            return (Target(service),)
    elif product == "linux" and service in LINUX_SERVICES and not category:
        return LINUX_SERVICES[service]
    raise SigmaError(f"unsupported logsource ({description or 'empty'})")
