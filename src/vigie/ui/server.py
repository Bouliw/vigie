"""``vigie ui``: the Vigie app, served to the browser from this computer only.

The server listens on 127.0.0.1 and hands out the same HTML report as
``vigie analyze``. Because it runs on the machine of a security analyst and
reads logs, it is strict about who talks to it:

* a random token is made at each launch and sent in the URL the browser opens;
  the first page turns it into a cookie (HttpOnly, SameSite=Strict), and
  every request needs it: as the cookie, and as an ``X-Vigie-Token`` header
  for anything that changes something (a page of another site cannot set it);
* the Host header must be ``127.0.0.1:<port>`` or ``localhost:<port>``, so a
  web page cannot reach the server through DNS rebinding;
* no CORS header is ever sent, and request bodies have a size limit;
* it reads only what an analysis needs: the logs the user picked, uploaded
  copies in a private temporary folder (deleted when the analysis ends and
  when the server stops), and the reports it wrote itself;
* it stops on Ctrl-C, or a few minutes after the last open page stopped
  checking in.
"""

from __future__ import annotations

import contextlib
import hmac
import json
import os
import re
import secrets
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser
from collections.abc import Callable
from datetime import datetime, timezone
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlsplit

from jinja2 import ChoiceLoader, Environment, PackageLoader, StrictUndefined

from vigie import __version__
from vigie.analysis import analyze
from vigie.atlas import default_atlas_data
from vigie.attack import default_attack_data
from vigie.collect import detect_format
from vigie.demo import DEMO_LOGS, DEMO_YEAR
from vigie.icons import ICONS_DIR
from vigie.models import LEVELS
from vigie.report.builder import build_report
from vigie.report.render import render_html, timestamp
from vigie.rules import RULES_DIR
from vigie.sigma.loader import RuleSet, load_rules
from vigie.timeutils import UTC
from vigie.userdirs import data_dir
from vigie.watch import FOLLOWED_FORMATS, FileSource, Source, Watcher, describe

PREFERRED_PORT = 47731  # the same port each launch keeps the theme the user picked
MAX_JSON = 64 * 1024
MAX_UPLOAD = 1024**3  # per file
MAX_UPLOAD_FILES = 5000
MAX_DRAIN = 16 * 1024 * 1024  # a refused body up to this size is read away so the 413 gets through
IDLE_TIMEOUT = 300.0  # seconds without any request before the server stops
RECENT_LIMIT = 20
COOKIE = "vigie_token"
REPORT_ID = re.compile(r"^\d{8}-\d{6}-[0-9a-f]{6}$")
TOKEN_ID = re.compile(r"^[0-9a-f]{24}$")


class HTTPError(Exception):
    def __init__(self, status: HTTPStatus, message: str) -> None:
        super().__init__(message)
        self.status = status


# --- Jobs: an analysis, or a watch, publishing events to the page ------------------


class Channel:
    """Events of one job, kept so a page that connects late (or again) gets them all."""

    def __init__(self, keep: int = 2000) -> None:
        self.events: list[tuple[int, str, dict[str, Any]]] = []
        self.finished = False
        self._next = 0
        self._keep = keep
        self._cond = threading.Condition()

    def emit(self, kind: str, data: dict[str, Any], *, final: bool = False) -> None:
        with self._cond:
            self.events.append((self._next, kind, data))
            self._next += 1
            # A long watch keeps its latest events only (the page holds the rest).
            if len(self.events) > self._keep:
                del self.events[: len(self.events) - self._keep]
            self.finished = self.finished or final
            self._cond.notify_all()

    def since(self, seq: int, timeout: float) -> tuple[list[tuple[int, str, dict[str, Any]]], bool]:
        with self._cond:
            if not any(event[0] >= seq for event in self.events) and not self.finished:
                self._cond.wait(timeout)
            return [event for event in self.events if event[0] >= seq], self.finished


class Analysis:
    """One analysis run by the app, in a thread."""

    def __init__(self, app: App, source: dict[str, Any]) -> None:
        self.app = app
        self.id = new_report_id()
        self.source = source
        self.channel = Channel()
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self) -> None:
        source = self.source
        path: Path = source["path"]
        last_match = [0.0]

        def progress(stage: str, **details: Any) -> None:
            if stage == "match":
                now = time.monotonic()
                if details["done"] < details["total"] and now - last_match[0] < 0.1:
                    return  # a few updates a second are enough for the page
                last_match[0] = now
            self.channel.emit("progress", {"stage": stage, **details})

        try:
            started = time.monotonic()
            ruleset = self.app.ruleset()
            self.channel.emit("progress", {"stage": "start", "rules": rule_count(ruleset)})
            result = analyze(path, rules=ruleset, year=source.get("year"), progress=progress)
            report = build_report(result, generated_at=datetime.now(UTC))
            folder = self.app.reports_dir / self.id
            folder.mkdir(parents=True, exist_ok=True)
            target = folder / "report.html"
            target.write_text(render_html(report), encoding="utf-8", errors="backslashreplace")
            entry = {
                "id": self.id,
                "label": source["label"],
                "kind": source["kind"],
                "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "events": report.event_count,
                "files": len(report.files),
                "skipped": len(report.skipped),
                "alerts": report.alert_count,
                "counts": report.level_counts,
                "hidden": sum(report.hidden_by_level.values()),
                "first": timestamp(report.first_event) if report.first_event else None,
                "last": timestamp(report.last_event) if report.last_event else None,
                "seconds": round(time.monotonic() - started, 2),
                "top": [
                    {"level": s.rule.level, "title": s.rule.title, "count": s.alert_count}
                    for s in report.rules[:3]
                ],
            }
            self.app.recent.add(entry)
            outcome = ("done", entry)
        except Exception as exc:  # the page must hear about any failure
            outcome = ("failed", {"message": friendly_error(exc)})
        # The uploaded copies are not needed any more: the report holds the evidence.
        if source.get("upload"):
            self.app.uploads.discard(source["upload"])
        self.channel.emit(*outcome, final=True)


class WatchSession:
    """Logs followed for the app's Watch tab, in a thread, until stopped."""

    def __init__(self, app: App, paths: list[Path], label: str) -> None:
        self.app = app
        self.id = secrets.token_hex(12)
        self.label = label
        self.channel = Channel()
        self.paused = False
        self.stopped = threading.Event()
        self.folder = Path(tempfile.mkdtemp(prefix="vigie-watch-", dir=app.temp_root))
        self.report_path = self.folder / "report.html"
        sources: list[Source] = [FileSource(path, detect_format(path) or "") for path in paths]
        self.watcher = Watcher(
            sources,
            app.ruleset(),
            self.report_path,
            notify_level=None,
            refresh=5,
            out=_Discard(),
            notifier=lambda title, message: None,
        )
        self.started = time.monotonic()
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self) -> None:
        watcher = self.watcher
        threshold = LEVELS.index(watcher.min_level)
        rates: list[tuple[float, int]] = []
        try:
            watcher.write_report(live=True)
            while not self.stopped.is_set():
                count = 0
                if not self.paused:
                    before = watcher.event_count
                    for alert in watcher.step():
                        if alert.rule.severity >= threshold:
                            self.channel.emit("alert", self.alert_data(alert))
                    count = watcher.event_count - before
                    watcher.update_report()
                now = time.monotonic()
                rates = [(t, n) for t, n in rates if now - t <= 10] + [(now, count)]
                span = max(1.0, now - rates[0][0]) if len(rates) > 1 else 1.0
                shown = [a for a in watcher.alerts if a.rule.severity >= threshold]
                self.channel.emit(
                    "status",
                    {
                        "sources": len(watcher.sources),
                        "events": watcher.event_count,
                        "rate": round(sum(n for _, n in rates) / span, 1),
                        "alerts": len(shown),
                        "counts": {
                            level: sum(1 for a in shown if a.rule.level == level)
                            for level in reversed(LEVELS[threshold:])
                        },
                        "paused": self.paused,
                        "seconds": int(now - self.started),
                    },
                )
                self.stopped.wait(1.0)
        except Exception as exc:
            self.channel.emit("failed", {"message": friendly_error(exc)})
        finally:
            for source in watcher.sources:
                with contextlib.suppress(Exception):
                    source.close()
            with contextlib.suppress(Exception):
                watcher.write_report(live=False)
            self.channel.emit("stopped", {"events": watcher.event_count}, final=True)

    def alert_data(self, alert: Any) -> dict[str, Any]:
        techniques = [
            technique.id
            for framework in (default_attack_data(), default_atlas_data())
            for technique in framework.map_tags(alert.rule.tags).techniques
        ]
        return {
            "level": alert.rule.level,
            "title": alert.rule.title,
            "time": timestamp(alert.last_seen),
            "techniques": techniques,
            "what": describe(alert)[:400],
        }


class _Discard:
    def write(self, text: str) -> int:
        return len(text)

    def flush(self) -> None:
        pass

    def isatty(self) -> bool:
        return False


# --- Stores ------------------------------------------------------------------------


class Recent:
    """The latest analyses made in the app, in ``recent.json`` next to their reports."""

    def __init__(self, folder: Path) -> None:
        self.file = folder / "recent.json"
        self.folder = folder
        self._lock = threading.Lock()

    def load(self) -> list[dict[str, Any]]:
        try:
            data = json.loads(self.file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        if not isinstance(data, list):
            return []
        return [
            entry
            for entry in data
            if isinstance(entry, dict) and REPORT_ID.match(str(entry.get("id", "")))
        ]

    def add(self, entry: dict[str, Any]) -> None:
        with self._lock:
            entries = [entry, *[e for e in self.load() if e["id"] != entry["id"]]]
            for old in entries[RECENT_LIMIT:]:
                shutil.rmtree(self.folder / old["id"], ignore_errors=True)
            self._write(entries[:RECENT_LIMIT])

    def remove(self, report_id: str) -> bool:
        with self._lock:
            entries = self.load()
            kept = [e for e in entries if e["id"] != report_id]
            if len(kept) == len(entries):
                return False
            shutil.rmtree(self.folder / report_id, ignore_errors=True)
            self._write(kept)
            return True

    def get(self, report_id: str) -> dict[str, Any] | None:
        return next((e for e in self.load() if e["id"] == report_id), None)

    def _write(self, entries: list[dict[str, Any]]) -> None:
        self.folder.mkdir(parents=True, exist_ok=True)
        partial = self.file.with_name(".recent.json.tmp")
        partial.write_text(json.dumps(entries, indent=1) + "\n", encoding="utf-8")
        partial.replace(self.file)


class Uploads:
    """Copies of the files the browser sends, each set in its own private folder."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self._lock = threading.Lock()
        self._sets: dict[str, dict[str, Any]] = {}

    def new(self) -> str:
        upload_id = secrets.token_hex(12)
        folder = self.root / upload_id
        folder.mkdir(mode=0o700)
        with self._lock:
            self._sets[upload_id] = {"folder": folder, "files": 0, "names": []}
        return upload_id

    def folder(self, upload_id: str) -> Path:
        with self._lock:
            entry = self._sets.get(upload_id)
        if entry is None:
            raise HTTPError(HTTPStatus.NOT_FOUND, "unknown upload")
        return entry["folder"]

    def add_file(self, upload_id: str, relative: str) -> Path:
        folder = self.folder(upload_id)
        parts = [part for part in relative.replace("\\", "/").split("/") if part not in ("", ".")]
        if not parts or any(part == ".." or ":" in part or "\x00" in part for part in parts):
            raise HTTPError(HTTPStatus.BAD_REQUEST, "invalid file name")
        target = folder.joinpath(*parts)
        if folder.resolve() not in target.resolve().parents:
            raise HTTPError(HTTPStatus.BAD_REQUEST, "invalid file name")
        with self._lock:
            entry = self._sets[upload_id]
            if entry["files"] >= MAX_UPLOAD_FILES:
                raise HTTPError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "too many files")
            entry["files"] += 1
            entry["names"].append("/".join(parts))
        target.parent.mkdir(parents=True, exist_ok=True)
        return target

    def names(self, upload_id: str) -> list[str]:
        with self._lock:
            return list(self._sets.get(upload_id, {}).get("names", []))

    def discard(self, upload_id: str) -> None:
        with self._lock:
            entry = self._sets.pop(upload_id, None)
        if entry:
            shutil.rmtree(entry["folder"], ignore_errors=True)


# --- The app -------------------------------------------------------------------------


class App:
    """State shared by the request handlers of one ``vigie ui`` run."""

    def __init__(
        self,
        *,
        token: str | None = None,
        reports_dir: Path | None = None,
        idle_timeout: float = IDLE_TIMEOUT,
        opener: Callable[[str], Any] = webbrowser.open,
        reveal: Callable[[Path], Any] | None = None,
    ) -> None:
        self.token = token or secrets.token_urlsafe(32)
        self.reports_dir = reports_dir or data_dir() / "reports"
        self.temp_root = Path(tempfile.mkdtemp(prefix="vigie-ui-"))
        os.chmod(self.temp_root, 0o700)
        self.uploads = Uploads(self.temp_root)
        self.recent = Recent(self.reports_dir)
        self.analyses: dict[str, Analysis] = {}
        self.watches: dict[str, WatchSession] = {}
        self.idle_timeout = idle_timeout
        self.last_seen = time.monotonic()
        self.opener = opener
        self.reveal = reveal or reveal_in_file_manager
        self.port = 0
        self._ruleset: RuleSet | None = None
        self._lock = threading.Lock()
        loader = ChoiceLoader(
            [PackageLoader("vigie.ui", "templates"), PackageLoader("vigie.report", "templates")]
        )
        self.templates = Environment(loader=loader, autoescape=True, undefined=StrictUndefined)

    def ruleset(self) -> RuleSet:
        with self._lock:
            if self._ruleset is None:
                self._ruleset = load_rules(RULES_DIR)
            return self._ruleset

    def touch(self) -> None:
        self.last_seen = time.monotonic()

    def idle(self) -> bool:
        return time.monotonic() - self.last_seen > self.idle_timeout

    def page(self) -> str:
        icon = (ICONS_DIR / "vigie.svg").read_text(encoding="utf-8")
        return self.templates.get_template("app.html.j2").render(
            token=self.token,
            max_upload=MAX_UPLOAD,
            version=__version__,
            rules=rule_count(self.ruleset()),
            platform=sys.platform,
            favicon="data:image/svg+xml," + _url_quote(icon),
        )

    def close(self) -> None:
        for session in list(self.watches.values()):
            session.stopped.set()
        for session in list(self.watches.values()):
            session.thread.join(timeout=5)
        shutil.rmtree(self.temp_root, ignore_errors=True)


def rule_count(ruleset: RuleSet) -> int:
    return len(ruleset.detections) + len(ruleset.correlations)


def new_report_id() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S-") + secrets.token_hex(3)


def friendly_error(exc: Exception) -> str:
    if isinstance(exc, FileNotFoundError):
        return f"Vigie could not find {exc.filename or exc}."
    if isinstance(exc, PermissionError):
        return f"Vigie is not allowed to read {exc.filename or 'this file'}."
    return f"The analysis stopped: {exc}"


def reveal_in_file_manager(path: Path) -> None:
    """Show ``path`` in Finder, Explorer or the Linux file manager."""
    if sys.platform == "darwin":
        command = ["open", "-R", str(path)]
    elif sys.platform == "win32":
        command = ["explorer", f"/select,{path}"]
    else:
        command = ["xdg-open", str(path.parent)]
    subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _url_quote(text: str) -> str:
    return quote(" ".join(text.split()), safe=" =:/,'")


def followable(path: Path) -> list[Path]:
    """Log files ``vigie watch`` can follow: the file itself, or those in a folder."""
    candidates = [path] if path.is_file() else sorted(p for p in path.rglob("*") if p.is_file())
    found = []
    for candidate in candidates[:2000]:
        if candidate.suffix == ".gz" or any(part.startswith(".") for part in candidate.parts[-1:]):
            continue
        try:
            if detect_format(candidate) in FOLLOWED_FORMATS:
                found.append(candidate)
        except OSError:
            continue
    return found


# --- HTTP ---------------------------------------------------------------------------


class Handler(BaseHTTPRequestHandler):
    server_version = "Vigie"
    sys_version = ""
    app: App  # set on the subclass made by make_server

    # Routing ------------------------------------------------------------------------

    def do_GET(self) -> None:
        self._serve("GET")

    def do_POST(self) -> None:
        self._serve("POST")

    def do_PUT(self) -> None:
        self._serve("PUT")

    def do_DELETE(self) -> None:
        self._serve("DELETE")

    def _serve(self, method: str) -> None:
        try:
            url = urlsplit(self.path)
            self._check_host()
            if method == "GET" and url.path == "/" and "token" in parse_qs(url.query):
                self._login(parse_qs(url.query)["token"][0])
                return
            self._check_token(state_changing=method != "GET")
            self.app.touch()
            self._route(method, url.path)
        except HTTPError as exc:
            self._send_json({"error": str(exc)}, exc.status)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _route(self, method: str, path: str) -> None:
        app = self.app
        parts = [unquote(part) for part in path.strip("/").split("/")] if path != "/" else []
        if method == "GET" and not parts:
            self._send(app.page().encode("utf-8"), "text/html; charset=utf-8", page=True)
        elif method == "GET" and parts == ["api", "state"]:
            self._send_json(
                {
                    "version": __version__,
                    "platform": sys.platform,
                    "recent": app.recent.load(),
                    "reports": str(app.reports_dir),
                    "watches": [
                        {"id": w.id, "label": w.label, "running": not w.stopped.is_set()}
                        for w in app.watches.values()
                    ],
                }
            )
        elif method == "POST" and parts == ["api", "heartbeat"]:
            self._read_json()
            self._send_json({"ok": True})
        elif method == "POST" and parts == ["api", "uploads"]:
            self._read_json()
            self._send_json({"id": app.uploads.new()}, HTTPStatus.CREATED)
        elif method == "PUT" and len(parts) >= 4 and parts[:2] == ["api", "uploads"]:
            self._receive_file(parts[2], "/".join(parts[3:]))
        elif method == "POST" and parts == ["api", "analyses"]:
            self._start_analysis(self._read_json())
        elif method == "GET" and len(parts) == 4 and parts[:2] == ["api", "analyses"]:
            if parts[3] != "events":
                raise HTTPError(HTTPStatus.NOT_FOUND, "not found")
            analysis = app.analyses.get(parts[2])
            if analysis is None:
                raise HTTPError(HTTPStatus.NOT_FOUND, "unknown analysis")
            self._stream(analysis.channel)
        elif method == "GET" and len(parts) == 3 and parts[0] == "reports":
            if parts[2] != "report.html":
                raise HTTPError(HTTPStatus.NOT_FOUND, "not found")
            self._send_file(self._report_file(parts[1]))
        elif method == "POST" and len(parts) == 4 and parts[:2] == ["api", "reports"]:
            self._read_json()
            report = self._report_file(parts[2])
            if parts[3] == "open":
                app.opener(report.resolve().as_uri())
            elif parts[3] == "reveal":
                app.reveal(report)
            else:
                raise HTTPError(HTTPStatus.NOT_FOUND, "not found")
            self._send_json({"ok": True})
        elif method == "DELETE" and len(parts) == 3 and parts[:2] == ["api", "reports"]:
            if not REPORT_ID.match(parts[2]) or not app.recent.remove(parts[2]):
                raise HTTPError(HTTPStatus.NOT_FOUND, "unknown report")
            self._send_json({"ok": True})
        elif method == "POST" and parts == ["api", "watches"]:
            self._start_watch(self._read_json())
        elif len(parts) >= 3 and parts[:2] == ["api", "watches"]:
            self._watch_action(method, parts[2], parts[3:])
        elif method == "GET" and len(parts) == 3 and parts[0] == "watches":
            session = app.watches.get(parts[1])
            if session is None or parts[2] != "report.html":
                raise HTTPError(HTTPStatus.NOT_FOUND, "not found")
            self._send_file(session.report_path)
        else:
            raise HTTPError(HTTPStatus.NOT_FOUND, "not found")

    # Security -------------------------------------------------------------------------

    def _check_host(self) -> None:
        host = (self.headers.get("Host") or "").lower()
        allowed = {f"127.0.0.1:{self.app.port}", f"localhost:{self.app.port}"}
        if host not in allowed:
            raise HTTPError(HTTPStatus.FORBIDDEN, "this server only answers to 127.0.0.1")

    def _check_token(self, *, state_changing: bool) -> None:
        header = self.headers.get("X-Vigie-Token")
        cookie = SimpleCookie(self.headers.get("Cookie") or "").get(COOKIE)
        given = header if state_changing else (header or (cookie.value if cookie else None))
        if not given or not hmac.compare_digest(given.encode(), self.app.token.encode()):
            raise HTTPError(HTTPStatus.FORBIDDEN, "missing or wrong token")
        origin = self.headers.get("Origin")
        port = self.app.port
        if origin and origin not in {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}:
            raise HTTPError(HTTPStatus.FORBIDDEN, "cross-origin request")

    def _login(self, token: str) -> None:
        if not hmac.compare_digest(token.encode(), self.app.token.encode()):
            raise HTTPError(HTTPStatus.FORBIDDEN, "wrong token")
        self.app.touch()
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", "/")
        self.send_header(
            "Set-Cookie", f"{COOKIE}={self.app.token}; HttpOnly; SameSite=Strict; Path=/"
        )
        self._common_headers()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _length(self, limit: int) -> int:
        if self.headers.get("Transfer-Encoding"):
            raise HTTPError(HTTPStatus.LENGTH_REQUIRED, "send a Content-Length")
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError as exc:
            raise HTTPError(HTTPStatus.BAD_REQUEST, "bad Content-Length") from exc
        if length < 0:
            raise HTTPError(HTTPStatus.BAD_REQUEST, "bad Content-Length")
        if length > limit:
            self.close_connection = True
            # Closing on an unread body resets the connection (on Windows, or once the body
            # outgrows the socket buffers) and the client never sees the 413: read it away first
            if length <= MAX_DRAIN:
                while length > 0:
                    chunk = self.rfile.read(min(length, 1024 * 1024))
                    if not chunk:
                        break
                    length -= len(chunk)
            raise HTTPError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "request body too large")
        return length

    def _read_json(self) -> dict[str, Any]:
        length = self._length(MAX_JSON)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(raw or b"{}")
        except ValueError as exc:
            raise HTTPError(HTTPStatus.BAD_REQUEST, "invalid JSON") from exc
        if not isinstance(data, dict):
            raise HTTPError(HTTPStatus.BAD_REQUEST, "expected a JSON object")
        return data

    # Actions ------------------------------------------------------------------------

    def _receive_file(self, upload_id: str, relative: str) -> None:
        if not TOKEN_ID.match(upload_id):
            raise HTTPError(HTTPStatus.NOT_FOUND, "unknown upload")
        length = self._length(MAX_UPLOAD)
        target = self.app.uploads.add_file(upload_id, relative)
        remaining = length
        with target.open("wb") as handle:
            while remaining:
                chunk = self.rfile.read(min(remaining, 1 << 20))
                if not chunk:
                    raise HTTPError(HTTPStatus.BAD_REQUEST, "upload cut short")
                handle.write(chunk)
                remaining -= len(chunk)
        modified = self.headers.get("X-Last-Modified")
        if modified and modified.isdigit():  # keeps the year guess of classic syslog files right
            seconds = int(modified) / 1000
            with contextlib.suppress(OSError, ValueError, OverflowError):
                os.utime(target, (seconds, seconds))
        self._send_json({"ok": True}, HTTPStatus.CREATED)

    def _start_analysis(self, body: dict[str, Any]) -> None:
        app = self.app
        kind = body.get("source")
        if kind == "sample":
            source = {"kind": "sample", "path": DEMO_LOGS, "year": DEMO_YEAR}
            source["label"] = "Sample logs"
        elif kind == "upload":
            upload_id = str(body.get("upload", ""))
            folder = app.uploads.folder(upload_id) if TOKEN_ID.match(upload_id) else None
            if folder is None:
                raise HTTPError(HTTPStatus.NOT_FOUND, "unknown upload")
            names = app.uploads.names(upload_id)
            if not names:
                raise HTTPError(HTTPStatus.BAD_REQUEST, "no file was uploaded")
            label = str(body.get("label") or names[0])[:200]
            source = {"kind": "upload", "path": folder, "upload": upload_id, "label": label}
        elif kind == "path":
            text = str(body.get("path", "")).strip().strip('"')
            if not text:
                raise HTTPError(HTTPStatus.BAD_REQUEST, "type the path of a log file or folder")
            path = Path(os.path.expanduser(text))
            if not path.exists():
                raise HTTPError(HTTPStatus.BAD_REQUEST, f"nothing at {path}")
            source = {"kind": "path", "path": path, "label": str(path)}
        else:
            raise HTTPError(HTTPStatus.BAD_REQUEST, "unknown source")
        analysis = Analysis(app, source)
        app.analyses[analysis.id] = analysis
        analysis.thread.start()
        self._send_json({"id": analysis.id}, HTTPStatus.CREATED)

    def _start_watch(self, body: dict[str, Any]) -> None:
        text = str(body.get("path", "")).strip().strip('"')
        if not text:
            raise HTTPError(HTTPStatus.BAD_REQUEST, "type the path of a log file or folder")
        path = Path(os.path.expanduser(text))
        if not path.exists():
            raise HTTPError(HTTPStatus.BAD_REQUEST, f"nothing at {path}")
        files = followable(path)
        if not files:
            raise HTTPError(
                HTTPStatus.BAD_REQUEST,
                "no log Vigie can follow there: watch follows auth.log files, macOS unified "
                "log exports (.ndjson) and AI agent logs (JSON Lines)",
            )
        session = WatchSession(self.app, files, str(path))
        self.app.watches[session.id] = session
        session.thread.start()
        self._send_json(
            {"id": session.id, "files": [str(f) for f in files], "label": str(path)},
            HTTPStatus.CREATED,
        )

    def _watch_action(self, method: str, watch_id: str, rest: list[str]) -> None:
        session = self.app.watches.get(watch_id)
        if session is None:
            raise HTTPError(HTTPStatus.NOT_FOUND, "unknown watch")
        if method == "GET" and rest == ["events"]:
            self._stream(session.channel)
        elif method == "POST" and rest == ["pause"]:
            session.paused = bool(self._read_json().get("paused", True))
            self._send_json({"paused": session.paused})
        elif method == "POST" and rest == ["stop"]:
            self._read_json()
            session.stopped.set()
            self._send_json({"ok": True})
        else:
            raise HTTPError(HTTPStatus.NOT_FOUND, "not found")

    def _report_file(self, report_id: str) -> Path:
        if not REPORT_ID.match(report_id) or self.app.recent.get(report_id) is None:
            raise HTTPError(HTTPStatus.NOT_FOUND, "unknown report")
        path = self.app.reports_dir / report_id / "report.html"
        if not path.is_file():
            raise HTTPError(HTTPStatus.NOT_FOUND, "the report file is gone")
        return path

    # Responses ----------------------------------------------------------------------

    def _stream(self, channel: Channel) -> None:
        """Server-Sent Events: every event of the channel, then the new ones as they come."""
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self._common_headers()
        self.end_headers()
        seq = 0
        while True:
            events, finished = channel.since(seq, timeout=15)
            for number, kind, data in events:
                payload = json.dumps(data, ensure_ascii=False)
                self.wfile.write(f"id: {number}\nevent: {kind}\ndata: {payload}\n\n".encode())
                seq = number + 1
            if not events:
                self.wfile.write(b": still here\n\n")
            self.wfile.flush()
            self.app.touch()
            if finished and not channel.since(seq, timeout=0)[0]:
                return

    def _send_file(self, path: Path) -> None:
        self._send(path.read_bytes(), "text/html; charset=utf-8", report=True)

    def _send_json(self, data: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        self._send(json.dumps(data).encode(), "application/json", status=status)

    def _send(
        self,
        body: bytes,
        content_type: str,
        *,
        status: HTTPStatus = HTTPStatus.OK,
        page: bool = False,
        report: bool = False,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self._common_headers()
        if page or report:
            ancestors = "'self'" if report else "'none'"
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                f"img-src data: 'self'; connect-src 'self'; frame-src 'self'; "
                f"frame-ancestors {ancestors}; base-uri 'none'; form-action 'none'",
            )
            self.send_header("X-Frame-Options", "SAMEORIGIN" if report else "DENY")
        self.end_headers()
        self.wfile.write(body)

    def _common_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")

    def log_message(self, format: str, *args: Any) -> None:
        pass  # requests are not logged: their paths can name the files being analyzed


class Server(ThreadingHTTPServer):
    daemon_threads = True
    # Reopening the app right after closing it gets the same port back (TIME_WAIT). Not on
    # Windows, where SO_REUSEADDR would let another program bind the same port.
    allow_reuse_address = sys.platform != "win32"

    def server_bind(self) -> None:
        # HTTPServer.server_bind looks up the host's full name, a reverse DNS query
        # that can take half a minute on some Macs and networks before the app
        # answers. The app never uses that name: bind without it.
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = str(host)
        self.server_port = int(port)


def _say(text: str) -> None:
    """Print at once: the installers keep this output in their log (pythonw has no stdout)."""
    if sys.stdout is not None:
        print(text, flush=True)


def make_server(app: App, port: int = 0) -> Server:
    """Bind to 127.0.0.1 on ``port`` (0: any free port); the app learns the port it got."""
    handler = type("AppHandler", (Handler,), {"app": app})
    server = Server(("127.0.0.1", port), handler)
    app.port = server.server_address[1]
    return server


def bind(app: App, port: int | None = None) -> Server:
    if port is not None:
        return make_server(app, port)
    try:
        return make_server(app, PREFERRED_PORT)
    except OSError:
        return make_server(app, 0)


def serve(
    *,
    port: int | None = None,
    open_browser: bool = True,
    say: Callable[[str], None] | None = None,
    idle_timeout: float = IDLE_TIMEOUT,
) -> int:
    """Run the app until Ctrl-C or until no page has checked in for ``idle_timeout`` seconds."""
    say = say or _say
    app = App(idle_timeout=idle_timeout)
    server = bind(app, port)
    url = f"http://127.0.0.1:{app.port}/?token={app.token}"

    def watchdog() -> None:
        while True:
            time.sleep(5)
            if app.idle():
                server.shutdown()
                return

    threading.Thread(target=watchdog, daemon=True).start()
    say(f"Vigie is running at {url}")
    say("Keep this window open while you use it; stop it with Ctrl-C.")
    if open_browser:
        # From a thread: a browser slow to start (a cold Safari takes seconds) must
        # not keep the app from answering the page it is opening.
        threading.Thread(target=app.opener, args=(url,), daemon=True).start()
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        app.close()
    say("Vigie stopped.")
    return 0
