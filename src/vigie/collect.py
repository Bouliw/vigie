"""Walk a folder of logs, detect each file's format and run the matching parser.

Formats are detected from the file *content* first (EVTX magic bytes, JSON
shape, syslog lines written by sshd/sudo...), and from the name only as a
hint, because collected logs are often renamed (``DC01-Security.evtx``,
``auth.log.3.gz``, ``export.json``, ``mac.ndjson``, ``agent.jsonl``).
"""

from __future__ import annotations

import itertools
import json
import re
import zipfile
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import tzinfo
from functools import partial
from pathlib import Path
from typing import Any

from vigie.models import Event
from vigie.parsers import ParseResult, agentlog, authlog, unifiedlog, winevtx, winjson
from vigie.timeutils import UTC

EVTX_MAGIC = b"ElfFile\x00"
AUTHLOG_NAME = re.compile(r"^(auth\.log|secure)([.-].*)?$")
SNIFF_LINES = 50
SNIFF_BYTES = 64 * 1024

# Called as progress(stage, **details) while an analysis runs, to show it (see analysis.py).
Progress = Callable[..., Any]


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
    """The format of a file: evtx, winjson, unifiedlog, agentlog, authlog, or ``None``."""
    with path.open("rb") as handle:
        head = handle.read(len(EVTX_MAGIC))
    if head == EVTX_MAGIC:
        return "evtx"

    suffixes = [suffix.lower() for suffix in path.suffixes]
    if suffixes[-1:] == [".zip"]:
        return "winjson" if _zip_has_json(path) else None
    if suffixes[-1:] in ([".json"], [".jsonl"], [".ndjson"]):
        return _json_format(path)
    if _looks_like_authlog(path):
        return "authlog"
    return None


def collect(
    root: str | Path,
    *,
    year: int | None = None,
    tz: tzinfo = UTC,
    progress: Progress | None = None,
) -> Collection:
    """Parse every supported file under ``root`` (a folder, searched recursively, or one file).

    ``year`` and ``tz`` are passed to the auth.log parser, see :func:`vigie.parsers.authlog.parse`.
    ``progress``, when given, is told which file is read (``"file"``) and how many events
    were read so far (``"parsed"``).
    """
    root = Path(root)
    if not root.exists():
        raise FileNotFoundError(f"no such file or directory: {root}")

    parsers: dict[str, Callable[[Path], ParseResult]] = {
        "evtx": winevtx.parse,
        "winjson": winjson.parse,
        "unifiedlog": unifiedlog.parse,
        "agentlog": agentlog.parse,
        "authlog": partial(authlog.parse, year=year, tz=tz),
    }
    base = root if root.is_dir() else root.parent
    collection = Collection()

    candidates = _candidate_files(root)
    for index, path in enumerate(candidates):
        relative = path.relative_to(base).as_posix()
        if progress:
            progress("file", path=relative, index=index, total=len(candidates))
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
        if progress:
            progress("parsed", path=relative, events=len(collection.events))

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


def _json_format(path: Path) -> str | None:
    """Tell Windows, macOS unified log and AI agent JSON logs apart by their first object."""
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in itertools.islice(handle, SNIFF_LINES):
            if not line.strip() or line.startswith(unifiedlog.STREAM_HEADER):
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                return None
            if not isinstance(data, dict):
                return None
            if "Channel" in data and "EventID" in data:
                return "winjson"
            if "eventMessage" in data or "eventType" in data:
                return "unifiedlog"
            if agentlog.dialect_of(data) is not None:
                return "agentlog"
            return None
    return None


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
