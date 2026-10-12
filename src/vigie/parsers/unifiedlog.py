"""Parser for the macOS unified log, as written by ``log show`` or ``log stream --style ndjson``.

Each line is one JSON object (``eventMessage``, ``processImagePath``,
``subsystem``, ``timestamp``...). Every log message becomes an
:class:`~vigie.models.Event` with ``source="unifiedlog"`` and the fields
``process``, ``subsystem``, ``category``, ``message_type`` and ``message``.
The messages below, all observed on macOS 27, also get an ``action`` field
and the values detection rules need:

* ``sshd``, ``sshd-session``, ``sshd-auth`` and ``sudo`` write the same
  messages as in a Linux auth.log; the auth.log parser reads them
  (``ssh_failed_password``, ``ssh_accepted``, ``sudo_auth_failure``...);
* ``opendirectoryd``: ``Authentication failed for <user> (<uuid>): <error>``,
  a wrong password for a local account, whatever asked for it
  (``local_auth_failure``);
* ``backgroundtaskmanagementd``: ``registerLaunchItem: result=no error, new
  item=...``, a launch agent, launch daemon or login item seen for the first
  time (``launch_item_added``);
* ``syspolicyd``: ``Adding Gatekeeper denial breadcrumb``, Gatekeeper refused
  to run some code (``gatekeeper_denied``), and ``Got bastion violation 0x...``,
  a behavioral detection of XProtect, whose bits are decoded to Apple's
  signature names (``xprotect_behavior``).

macOS redacts the dynamic parts of most messages: user names often read
``<private>``, so the account is identified by its UUID instead.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from vigie.models import Event
from vigie.parsers import authlog
from vigie.parsers.base import ParseResult
from vigie.timeutils import parse_iso8601

SOURCE = "unifiedlog"

# The entries Vigie's rules read. `vigie watch --macos` streams them with
# `log stream --level info --predicate PREDICATE`; the README gives the
# `log show` command that exports them for `vigie analyze`.
PREDICATE = (
    'process BEGINSWITH "sshd"'
    ' OR (process == "sudo" AND eventMessage CONTAINS " ; COMMAND=")'
    ' OR (process == "opendirectoryd" AND eventMessage BEGINSWITH "Authentication failed for")'
    ' OR (process == "backgroundtaskmanagementd"'
    ' AND eventMessage BEGINSWITH "registerLaunchItem: result=no error, new item=")'
    ' OR (process == "syspolicyd"'
    ' AND (eventMessage BEGINSWITH "Adding Gatekeeper denial breadcrumb"'
    ' OR eventMessage BEGINSWITH "Got bastion violation"))'
)

# XProtect behavioral detections ("bastion" rules): bit -> signature name, from
# BastionMeta.plist in XProtect 163 (Apple's spelling kept). A bit added by a
# later XProtect update shows as "unknown-0x...".
BASTION_SIGNATURES = {
    0x1: "macOS.Browser.Generic",
    0x2: "macOS.Messages.Generic",
    0x4: "macOS.QntDb.Generic",
    0x8: "macOS.NetworkSniffer.Generic",
    0x10: "macOS.HiddenPrivilegedHelpers.Generic",
    0x20: "macOS.ADLOAD.NumericPath",
    0x40: "macOS.ADLOAD.PersistenceSearch",
    0x80: "macOS.Persistence.HiddenAppSupport.Generic",
    0x100: "macOS.Safari.ExtensionModification",
    0x200: "macOS.Persistence.HiddenShared.Generic",
    0x400: "macOS.Persistence.HiddenShared.Exec",
    0x800: "macOS.InfoStealer.Generic",
    0x1000: "macOS.PasswordExtension.Exec",
    0x2000: "macOS.AppleEvents.Browsers",
    0x4000: "macOS.AppleEvents.LocalData",
    0x8000: "macOS.DataExfil.Clipboard",
    0x10000: "macOS.Persistence.ShellProfileFiles",
    0x20000: "macOS.Injection.GetTaskForPort",
    0x40000: "macOS.Execution.TempDir",
    0x80000: "macOS.DataExfil.Keychain",
    0x100000: "macOS.Network.Outgoing",
    0x200000: "macOS.Exectution.UnusualDylibLocation",
    0x400000: "macOS.Persistence.Launchplists",
    0x800000: "macOS.Injection.Debugee",
    0x1000000: "macOS.Location.Access",
    0x2000000: "macOS.Audio.Access",
    0x4000000: "macOS.ScreenCapture.Access",
    0x8000000: "macOS.InputMonitoring.Access",
    0x10000000: "macOS.ScreenCapture.Exec",
}

# `log stream` starts with this line, before the first JSON object.
STREAM_HEADER = "Filtering the log data"
_OFFSET = re.compile(r"([+-]\d{2})(\d{2})$")  # "+0200" -> "+02:00" (Python 3.10)
_NULL = "(null)"

_AUTH_FAILED = re.compile(
    r"^Authentication failed for (?P<user>.*) \((?P<account_uuid>[0-9A-Fa-f-]{36})\): "
    r"(?P<od_error>\S+)$"
)
_NEW_LAUNCH_ITEM = re.compile(
    r"^registerLaunchItem: result=no error, new item=.*?name=(?P<item_name>.*?), "
    r"type=(?P<item_type>[^,]+), disposition=\[(?P<item_disposition>[^\]]*)\], "
    r"identifier=(?:\d+\.)?(?P<item_identifier>[^,]*), url=(?P<item_url>.*)$"
)
_GATEKEEPER_DENIAL = re.compile(r"^Adding Gatekeeper denial breadcrumb \((?P<gk_check>[^)]*)\): ")
# The code identity syspolicyd prints: "PST: (path: 9c6d...), (team: X), (id: Y), (bundle_id: Z)".
_PST = re.compile(
    r"\(team: (?P<team_id>\(null\)|[^)]*)\), \(id: (?P<signing_id>\(null\)|[^)]*)\), "
    r"\(bundle_id: (?P<bundle_id>\(null\)|[^)]*)\)"
)
_BASTION = re.compile(r"^Got bastion violation 0x(?P<mask>[0-9A-Fa-f]+) ")


def parse(path: str | Path) -> ParseResult:
    """Parse a file written by ``log show`` or ``log stream`` with ``--style ndjson``."""
    path = Path(path)
    result = ParseResult()
    with path.open(encoding="utf-8", errors="replace") as handle:
        for lineno, raw in enumerate(handle, start=1):
            event = parse_line(raw, origin=f"{path.name}:{lineno}", warnings=result.warnings)
            if event is not None:
                result.events.append(event)
    return result


def parse_line(raw: str, *, origin: str, warnings: list[str]) -> Event | None:
    """The event of one ndjson line, or ``None`` for a line that holds no log message."""
    text = raw.strip()
    if not text or text.startswith(STREAM_HEADER):
        return None
    try:
        record = json.loads(text)
    except json.JSONDecodeError:
        warnings.append(f"{origin}: not a JSON object")
        return None
    # Skip what is not a log message: activities, signposts, boot markers, and
    # the {"count": ..., "finished": 1} line that ends `log show`.
    if not isinstance(record, dict) or record.get("eventType", "logEvent") != "logEvent":
        return None
    if "eventMessage" not in record:
        return None
    try:
        timestamp = parse_iso8601(_OFFSET.sub(r"\1:\2", str(record.get("timestamp", ""))))
    except ValueError as exc:
        warnings.append(f"{origin}: {exc}")
        return None

    process_path = _text(record.get("processImagePath"))
    process = process_path.rsplit("/", 1)[-1]
    message = _text(record.get("eventMessage"))
    fields = {
        "process": process,
        "process_path": process_path,
        "pid": _text(record.get("processID")),
        "user_id": _text(record.get("userID")),
        "subsystem": _text(record.get("subsystem")),
        "category": _text(record.get("category")),
        "message_type": _text(record.get("messageType")),
        "message": message,
    }
    fields = {name: value for name, value in fields.items() if value}
    fields.update(extract_action(process, message))
    return Event(timestamp=timestamp, source=SOURCE, fields=fields, raw=text, origin=origin)


def extract_action(process: str, message: str) -> dict[str, Any]:
    """The ``action`` of a message Vigie understands and its values, or ``{}``."""
    if process in authlog.AUTH_PROGRAMS:
        return authlog.extract_action(process, message)
    if process == "opendirectoryd" and (match := _AUTH_FAILED.match(message)):
        return {"action": "local_auth_failure", **_known(match.groupdict())}
    if process == "backgroundtaskmanagementd" and (match := _NEW_LAUNCH_ITEM.match(message)):
        values = _known(match.groupdict())
        url = urlsplit(values.get("item_url", ""))
        if url.scheme == "file":
            values["item_path"] = unquote(url.path)
        return {"action": "launch_item_added", **values}
    if process == "syspolicyd":
        if match := _GATEKEEPER_DENIAL.match(message):
            identity = _PST.search(message)
            return {
                "action": "gatekeeper_denied",
                **_known(match.groupdict()),
                **_known(identity.groupdict() if identity else {}),
            }
        if match := _BASTION.match(message):
            mask = int(match["mask"], 16)
            return {
                "action": "xprotect_behavior",
                "bastion_mask": hex(mask),
                "signature": bastion_signatures(mask),
            }
    return {}


def bastion_signatures(mask: int) -> tuple[str, ...]:
    """The XProtect signature names of the bits set in a bastion violation mask."""
    bits = [1 << index for index in range(mask.bit_length()) if mask >> index & 1]
    return tuple(BASTION_SIGNATURES.get(bit, f"unknown-{bit:#x}") for bit in bits)


def _known(values: dict[str, str | None]) -> dict[str, str]:
    """Drop the values macOS did not give: missing, ``(null)`` or redacted ``<private>``."""
    return {
        key: value for key, value in values.items() if value not in (None, "", _NULL, "<private>")
    }


def _text(value: Any) -> str:
    return "" if value is None else str(value)
