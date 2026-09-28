"""Walk a folder of logs, detect each file's format and run the matching parser.

Formats are detected from the file *content* first (EVTX magic bytes, JSON
shape, syslog lines written by sshd/sudo...), and from the name only as a
hint, because collected logs are often renamed (``DC01-Security.evtx``,
``auth.log.3.gz``, ``export.json``).
"""

from __future__ import annotations

import json
import re
import zipfile
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import tzinfo
from functools import partial
from pathlib import Path

from vigie.models import Event
from vigie.parsers import ParseResult, authlog, winevtx, winjson
from vigie.timeutils import UTC

EVTX_MAGIC = b"ElfFile\x00"
AUTHLOG_NAME = re.compile(r"^(auth\.log|secure)([.-].*)?$")
SNIFF_LINES = 50
SNIFF_BYTES = 64 * 1024


@dataclass
class FileReport:
    """What happened to one input file, for the report's ingestion statistics."""

    path: str
    format: str
    events: int
    warnings: list[str] = field(default_factory=list)


@dataclass
class Collection:
    """All events read from an input folder, sorted by time."""

    events: list[Event] = field(default_factory=list)
    files: list[FileReport] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


def detect_format(path: Path) -> str | None:
    """Return ``"evtx"``, ``"winjson"``, ``"authlog"`` or ``None`` if the file is not supported."""
    with path.open("rb") as handle:
        head = handle.read(len(EVTX_MAGIC))
    if head == EVTX_MAGIC:
        return "evtx"

    suffixes = [suffix.lower() for suffix in path.suffixes]
    if suffixes[-1:] == [".zip"]:
        return "winjson" if _zip_has_json(path) else None
    if suffixes[-1:] in ([".json"], [".jsonl"]):
        return "winjson" if _looks_like_windows_json(path) else None
    if _looks_like_authlog(path):
        return "authlog"
    return None


def collect(root: str | Path, *, year: int | None = None, tz: tzinfo = UTC) -> Collection:
    """Parse every supported file under ``root`` (a folder, searched recursively, or one file).

    ``year`` and ``tz`` are passed to the auth.log parser, see :func:`vigie.parsers.authlog.parse`.
    """
    root = Path(root)
    if not root.exists():
        raise FileNotFoundError(f"no such file or directory: {root}")

    parsers: dict[str, Callable[[Path], ParseResult]] = {
        "evtx": winevtx.parse,
        "winjson": winjson.parse,
        "authlog": partial(authlog.parse, year=year, tz=tz),
    }
    base = root if root.is_dir() else root.parent
    collection = Collection()

    for path in _candidate_files(root):
        relative = path.relative_to(base).as_posix()
        try:
            fmt = detect_format(path)
        except OSError as exc:
            collection.skipped.append(f"{relative} (unreadable: {exc.strerror or exc})")
            continue
        if fmt is None:
            collection.skipped.append(f"{relative} (unsupported format)")
            continue
        try:
            result = parsers[fmt](path)
        except Exception as exc:  # one broken file must not abort the whole analysis
            collection.files.append(FileReport(relative, fmt, 0, [f"parser failed: {exc!r}"]))
            continue
        collection.events.extend(result.events)
        collection.files.append(FileReport(relative, fmt, len(result.events), result.warnings))

    # sort() is stable: events with the same timestamp keep their file order.
    collection.events.sort(key=lambda event: event.timestamp)
    return collection


def _candidate_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    return sorted(
        path
        for path in root.rglob("*")
        if path.is_file() and not any(part.startswith(".") for part in path.relative_to(root).parts)
    )


def _zip_has_json(path: Path) -> bool:
    try:
        with zipfile.ZipFile(path) as archive:
            return any(name.endswith((".json", ".jsonl")) for name in archive.namelist())
    except zipfile.BadZipFile:
        return False


def _looks_like_windows_json(path: Path) -> bool:
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if line.strip():
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    return False
                return isinstance(data, dict) and "Channel" in data and "EventID" in data
    return False


def _looks_like_authlog(path: Path) -> bool:
    name = path.name[:-3] if path.name.endswith(".gz") else path.name
    if AUTHLOG_NAME.match(name):
        return True
    try:
        with authlog.open_text(path) as handle:
            # Bounded read: a large binary file may contain no newline at all.
            lines = handle.read(SNIFF_BYTES).splitlines()[:SNIFF_LINES]
    except (OSError, EOFError):
        return False
    return any(authlog.is_auth_line(line) for line in lines)
