"""Helpers shared by the Windows parsers (EVTX files and OTRF JSON exports)."""

from __future__ import annotations

import json
from typing import Any

# Windows channel -> Vigie source. The source names are the Sigma "service"
# names, so a rule with `logsource: {product: windows, service: sysmon}` is
# routed to events whose source is "sysmon".
CHANNEL_SOURCES = {
    "security": "security",
    "system": "system",
    "application": "application",
    "microsoft-windows-sysmon/operational": "sysmon",
    "microsoft-windows-powershell/operational": "powershell",
    "windows powershell": "powershell-classic",
    "microsoft-windows-taskscheduler/operational": "taskscheduler",
    "microsoft-windows-windows defender/operational": "windefend",
}


def channel_to_source(channel: str) -> str:
    """Map a Windows channel name to a Vigie source (unknown channels are kept, lowercased)."""
    return CHANNEL_SOURCES.get(channel.lower(), channel.lower())


def field_value(value: Any) -> str | tuple[str, ...]:
    """Normalize a raw field value to a string (or a tuple of strings for repeated values).

    Detection rules compare text, so numbers are stringified here once rather
    than in every rule: EventID 4625 and "4625" must match the same way.
    """
    if isinstance(value, dict) and "#text" in value:
        value = value["#text"]
    if value is None:
        return ""
    if isinstance(value, list):
        return tuple(str(field_value(item)) for item in value)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)
