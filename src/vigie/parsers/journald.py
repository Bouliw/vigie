"""Parser for the systemd journal, as ``journalctl --output=json`` prints it.

Distributions that keep their logs in the journal only (Fedora, Arch,
RHEL 9, Debian 12 and later without rsyslog) have no auth.log. Each journal
entry written by an authentication program (``sshd``, ``sudo``, ``su``,
``useradd``...) is turned back into the RFC 3339 syslog line rsyslog would
have written, and read by the auth.log parser: the events, fields and rules
are the same as for an auth.log.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any

from vigie.models import Event
from vigie.parsers import authlog
from vigie.timeutils import UTC

SOURCE_NAME = "journald"
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
# The programs whose entries are read: those the auth.log parser knows.
IDENTIFIERS = tuple(sorted(authlog.AUTH_PROGRAMS))


def _field(record: dict[str, Any], name: str) -> str | None:
    """A journal field as text. Repeated fields come as a list (first value kept);
    a value that is not valid UTF-8 comes as a list of byte values."""
    value = record.get(name)
    if isinstance(value, list) and value and all(isinstance(item, int) for item in value):
        return bytes(item & 0xFF for item in value).decode("utf-8", errors="replace")
    if isinstance(value, list):
        value = value[0] if value else None
        if isinstance(value, list):  # a repeated field whose first value is binary
            return _field({name: value}, name)
    return None if value is None else str(value)


def to_syslog_line(record: dict[str, Any]) -> str | None:
    """The auth.log line of a journal entry, or ``None`` if it has no message or time."""
    message = _field(record, "MESSAGE")
    realtime = _field(record, "__REALTIME_TIMESTAMP")
    program = _field(record, "SYSLOG_IDENTIFIER") or _field(record, "_COMM")
    if message is None or program is None or not (realtime or "").isdigit():
        return None
    when = EPOCH + timedelta(microseconds=int(realtime or 0))
    host = (_field(record, "_HOSTNAME") or "localhost").replace(" ", "_") or "localhost"
    pid = _field(record, "SYSLOG_PID") or _field(record, "_PID")
    tag = f"{program}[{pid}]" if pid and pid.isdigit() else program
    # One entry is one line: a message spanning several lines cannot pose as a second entry.
    text = " ".join(message.splitlines())
    return f"{when.isoformat(timespec='microseconds')} {host} {tag}: {text}"


def parse_line(text: str, *, lineno: int, now: datetime, warnings: list[str]) -> list[Event]:
    """The events of one line of ``journalctl --output=json``."""
    origin = f"{SOURCE_NAME}:{lineno}"
    try:
        record = json.loads(text)
    except ValueError:
        if text.strip():
            warnings.append(f"{origin}: not a JSON journal entry")
        return []
    if not isinstance(record, dict):
        warnings.append(f"{origin}: not a JSON journal entry")
        return []
    line = to_syslog_line(record)
    if line is None:
        return []
    result = authlog.parse_line(line, name=SOURCE_NAME, lineno=lineno, now=now)
    warnings += result.warnings
    return result.events
