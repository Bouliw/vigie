"""Parser for Linux authentication logs (``/var/log/auth.log``, ``/var/log/secure``).

Two line formats are supported:

* classic syslog (RFC 3164): ``Mar  3 10:15:01 web01 sshd[812]: ...``. It has
  no year and no timezone, so both must be supplied or inferred;
* RFC 3339, the rsyslog default on recent Debian and Ubuntu:
  ``2024-03-03T10:15:01.123456+01:00 web01 sshd[812]: ...``.

Every line becomes an :class:`~vigie.models.Event` with ``source="auth"``. Lines
from ``sshd``, ``sudo``, ``su`` and ``useradd`` that match a known message get an
``action`` field plus the values detection rules need (``user``, ``src_ip``...).
"""

from __future__ import annotations

import gzip
import re
from dataclasses import dataclass
from datetime import datetime, tzinfo
from itertools import pairwise
from pathlib import Path
from typing import TextIO

from vigie.models import Event
from vigie.parsers.base import ParseResult
from vigie.timeutils import UTC, parse_iso8601

SOURCE = "auth"

_MONTHS = {
    name: index
    for index, name in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
        start=1,
    )
}

_CLASSIC_HEADER = re.compile(
    r"^(?P<month>[A-Z][a-z]{2}) {1,2}(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) (?P<rest>.*)$"
)
_ISO_HEADER = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})) "
    r"(?P<host>\S+) (?P<rest>.*)$"
)
_PROGRAM = re.compile(r"^(?P<program>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?: (?P<message>.*)$")

# rsyslog folds identical consecutive messages into this summary line.
_REPEATED = re.compile(r"^message repeated (?P<count>\d+) times: \[ ?(?P<message>.*?) ?\]$")
# Most events one summary line can expand to. rsyslog only folds repeats within
# its flush interval (a few dozen at most), so a larger count is a forged line.
MAX_REPEAT = 1000

# Programs whose presence identifies an authentication log when sniffing a file.
# Since OpenSSH 9.8, per-connection messages come from "sshd-session" (and
# pre-authentication ones from "sshd-auth" since 10.0) instead of "sshd".
AUTH_PROGRAMS = frozenset(
    {"sshd", "sshd-session", "sshd-auth", "sudo", "su", "useradd", "userdel", "passwd", "login"}
)
_PROGRAM_FAMILY = {"sshd-session": "sshd", "sshd-auth": "sshd"}

# An IPv4 or IPv6 address as OpenSSH logs it (never a host name).
_IP = r"[0-9A-Fa-f:.]+"

# "Failed <method> for [invalid user ]<user> from <ip> port <port> ssh2[: <key info>]".
# The user name is chosen by the client and may contain spaces or a fake
# "from <ip> port <n> ssh2": see _parse_failed_login for how the source is found.
_FAILED_LOGIN = re.compile(r"^Failed (?P<auth_method>\S+) for (?P<rest>.*)$")
_LOGIN_SOURCE = re.compile(rf" from (?P<src_ip>{_IP}) port (?P<src_port>\d+) ssh2(?=: |$)")
# Methods whose failure message has nothing after "ssh2" (no key information).
_NO_SUFFIX_METHODS = frozenset({"password", "keyboard-interactive/pam", "none"})

# (program, action, pattern). The first matching pattern wins; named groups
# become event fields.
_MESSAGE_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    (
        "sshd",
        "ssh_accepted",
        # The user is an existing account (no spaces), so the first "from" is the source.
        re.compile(
            rf"^Accepted (?P<auth_method>\S+) for (?P<user>\S+) from (?P<src_ip>{_IP}) "
            r"port (?P<src_port>\d+) ssh2(?:: .*)?$"
        ),
    ),
    (
        "sshd",
        "ssh_invalid_user",
        # Nothing follows the port, so the last "from" is the source.
        re.compile(
            rf"^Invalid user (?P<user>.*) from (?P<src_ip>{_IP})(?: port (?P<src_port>\d+))?$"
        ),
    ),
    (
        "sudo",
        "sudo_auth_failure",
        # HOST= appears with "Defaults log_host", CHROOT= with a sudoers chroot.
        re.compile(
            r"^\s*(?P<user>\S+) : (?P<attempts>\d+) incorrect password attempts? ; "
            r"(?:HOST=(?P<sudo_host>\S+) ; )?(?:TTY=(?P<tty>\S+) ; )?(?:CHROOT=\S+ ; )?"
            r"PWD=(?P<pwd>.+?) ; USER=(?P<target_user>\S+) ; (?:.*?; )?COMMAND=(?P<command>.*)$"
        ),
    ),
    (
        "sudo",
        "sudo_command",
        re.compile(
            r"^\s*(?P<user>\S+) : (?:HOST=(?P<sudo_host>\S+) ; )?(?:TTY=(?P<tty>\S+) ; )?"
            r"(?:CHROOT=\S+ ; )?PWD=(?P<pwd>.+?) ; USER=(?P<target_user>\S+) ; "
            r"(?:.*?; )?COMMAND=(?P<command>.*)$"
        ),
    ),
    (
        "su",
        "su_session",
        re.compile(
            r"^pam_unix\(su(?:-l)?:session\): session opened for user "
            r"(?P<target_user>[^\s(]+)(?:\(uid=\d+\))? by (?P<user>[^\s(]*)"
        ),
    ),
    (
        "useradd",
        "user_created",
        re.compile(
            r"^new user: name=(?P<user>[^,]+), UID=(?P<uid>\d+), GID=(?P<gid>\d+), "
            r"home=(?P<home>[^,]+), shell=(?P<shell>[^,]+)"
        ),
    ),
]


@dataclass
class _Line:
    """A line whose header was recognized, before its timestamp is resolved."""

    lineno: int
    raw: str
    host: str
    rest: str
    timestamp: datetime | None = None  # set for RFC 3339 lines
    month: int = 0  # set for classic lines, with day and clock
    day: int = 0
    clock: str = ""


def parse(path: str | Path, *, year: int | None = None, tz: tzinfo = UTC) -> ParseResult:
    """Parse an auth.log file (plain text or ``.gz``).

    Args:
        path: File to read.
        year: Year of the first classic-syslog line. When omitted it is
            inferred so that the last line falls in the year the file was last
            modified, which is right for a log copied soon after rotation.
        tz: Timezone of classic-syslog timestamps (the host's local time).
            RFC 3339 lines carry their own offset and ignore it.
    """
    path = Path(path)
    result = ParseResult()
    with open_text(path) as handle:
        lines = _read_headers(handle, path.name, result)

    first_year = year if year is not None else _infer_first_year(path, lines)
    rollovers = 0
    previous_month = 0
    for line in lines:
        timestamp = line.timestamp
        if timestamp is None:
            # Classic syslog has no year: a month going backwards (Dec -> Jan)
            # means the log crossed a new year.
            if line.month < previous_month:
                rollovers += 1
            previous_month = line.month
            try:
                naive = datetime.strptime(
                    f"{first_year + rollovers}-{line.month:02d}-{line.day:02d} {line.clock}",
                    "%Y-%m-%d %H:%M:%S",
                )
            except ValueError as exc:
                result.warnings.append(f"{path.name}:{line.lineno}: invalid date ({exc})")
                continue
            timestamp = naive.replace(tzinfo=tz)
        result.events.extend(_build_events(path, line, timestamp, result.warnings))
    return result


def is_auth_line(line: str) -> bool:
    """True if ``line`` is a syslog line written by an authentication program."""
    match = _ISO_HEADER.match(line) or _CLASSIC_HEADER.match(line)
    if not match:
        return False
    program = _PROGRAM.match(match["rest"])
    return program is not None and program["program"] in AUTH_PROGRAMS


def open_text(path: Path) -> TextIO:
    """Open a log file as text, transparently decompressing ``.gz`` files."""
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


def _read_headers(handle: TextIO, name: str, result: ParseResult) -> list[_Line]:
    lines: list[_Line] = []
    for lineno, text in enumerate(handle, start=1):
        raw = text.rstrip("\r\n")
        if not raw.strip():
            continue
        if match := _ISO_HEADER.match(raw):
            try:
                timestamp = parse_iso8601(match["ts"])
            except ValueError as exc:
                result.warnings.append(f"{name}:{lineno}: {exc}")
                continue
            lines.append(_Line(lineno, raw, match["host"], match["rest"], timestamp=timestamp))
        elif (match := _CLASSIC_HEADER.match(raw)) and match["month"] in _MONTHS:
            lines.append(
                _Line(
                    lineno,
                    raw,
                    match["host"],
                    match["rest"],
                    month=_MONTHS[match["month"]],
                    day=int(match["day"]),
                    clock=match["time"],
                )
            )
        else:
            result.warnings.append(f"{name}:{lineno}: unrecognized syslog line")
    return lines


def _infer_first_year(path: Path, lines: list[_Line]) -> int:
    classic = [line.month for line in lines if line.timestamp is None]
    rollovers = sum(1 for prev, cur in pairwise(classic) if cur < prev)
    last_year = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC).year
    return last_year - rollovers


def _build_events(path: Path, line: _Line, timestamp: datetime, warnings: list[str]) -> list[Event]:
    """Build the event of a line, or one event per repetition of a folded line.

    rsyslog's RepeatedMsgReduction (enabled by default on Ubuntu) replaces
    identical consecutive messages with "message repeated N times: [ msg]",
    written after the first occurrence. Each of the N repetitions is a real
    attempt (a brute force tries several passwords per connection), so each
    becomes an event, marked with ``repeated`` and a distinct origin. The
    count comes from the file, so it is capped at :data:`MAX_REPEAT`; a count
    of 0, which rsyslog never writes, leaves the line as one plain event.
    """
    program = _PROGRAM.match(line.rest)
    repeated = _REPEATED.match(program["message"]) if program else None
    if program is None or repeated is None:
        return [_build_event(path, line, timestamp)]
    count = int(repeated["count"])
    if count == 0:
        warnings.append(f"{path.name}:{line.lineno}: repeat count of 0, line kept as is")
        return [_build_event(path, line, timestamp)]
    expanded = count
    if count > MAX_REPEAT:
        warnings.append(
            f"{path.name}:{line.lineno}: repeat count {count} capped at {MAX_REPEAT} events"
        )
        expanded = MAX_REPEAT
    return [
        _build_event(
            path,
            line,
            timestamp,
            message=repeated["message"],
            extra={"repeated": str(count)},
            origin=f"{path.name}:{line.lineno} (repeat {index}/{count})",
        )
        for index in range(1, expanded + 1)
    ]


def _build_event(
    path: Path,
    line: _Line,
    timestamp: datetime,
    *,
    message: str | None = None,
    extra: dict[str, str] | None = None,
    origin: str | None = None,
) -> Event:
    fields: dict[str, str] = {"host": line.host}
    if match := _PROGRAM.match(line.rest):
        program = match["program"]
        fields["program"] = program
        if match["pid"]:
            fields["pid"] = match["pid"]
        fields["message"] = match["message"] if message is None else message
        fields.update(_extract_action(program, fields["message"]))
    else:
        fields["message"] = line.rest
    fields.update(extra or {})

    return Event(
        timestamp=timestamp,
        source=SOURCE,
        host=line.host,
        fields=fields,
        raw=line.raw,
        origin=origin or f"{path.name}:{line.lineno}",
    )


def _extract_action(program: str, message: str) -> dict[str, str]:
    program = _PROGRAM_FAMILY.get(program, program)
    if program == "sshd" and (failed := _parse_failed_login(message)) is not None:
        return failed
    for expected_program, action, pattern in _MESSAGE_PATTERNS:
        if program != expected_program:
            continue
        if match := pattern.match(message):
            values = {key: value for key, value in match.groupdict().items() if value is not None}
            return {"action": action, **values}
    return {}


def _parse_failed_login(message: str) -> dict[str, str] | None:
    """Parse an sshd "Failed <method> for ..." message without trusting the user name.

    The client chooses the user name, and OpenSSH logs it with its spaces, so
    "x from 192.0.2.10 port 1 ssh2" is a valid user name that would put a fake
    source in front of the real one. For password and keyboard-interactive
    failures nothing follows "ssh2", so the real source is the one that ends the
    line. Public key failures end with key information, which may also hold
    client-chosen text (a certificate key ID): when several sources appear, the
    line is kept but no address is attributed rather than possibly the wrong one.
    """
    match = _FAILED_LOGIN.match(message)
    if match is None:
        return None
    rest = match["rest"]
    invalid_user = rest.startswith("invalid user ")
    if invalid_user:
        rest = rest.removeprefix("invalid user ")
    sources = list(_LOGIN_SOURCE.finditer(rest))
    if not sources:
        return None

    fields = {
        "action": "ssh_failed_password",
        "auth_method": match["auth_method"],
        "invalid_user": "true" if invalid_user else "false",
    }
    if match["auth_method"] in _NO_SUFFIX_METHODS:
        source = sources[-1] if sources[-1].end() == len(rest) else None
    else:
        source = sources[0] if len(sources) == 1 else None
    if source is None:
        fields["source_ambiguous"] = "true"
        return fields
    fields["user"] = rest[: source.start()]
    fields["src_ip"] = source["src_ip"]
    fields["src_port"] = source["src_port"]
    return fields
