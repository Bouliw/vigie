"""The local app (``vigie ui``): who may talk to it, what it accepts, and a full analysis."""

import http.client
import json
import shutil
import socket
import threading
import time
from pathlib import Path

import pytest

from vigie.ui import server as ui
from vigie.ui.server import App, Recent, make_server

FIXTURES = Path(__file__).parent / "fixtures"
TOKEN = "test-token-" + "x" * 32


@pytest.fixture
def app(tmp_path):
    opened, revealed = [], []
    app = App(
        token=TOKEN,
        reports_dir=tmp_path / "reports",
        opener=opened.append,
        reveal=revealed.append,
    )
    app.opened, app.revealed = opened, revealed
    server = make_server(app, 0)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
    thread.start()
    yield app
    server.shutdown()
    server.server_close()
    thread.join()
    app.close()


def request(app, method, path, body=None, *, token=TOKEN, cookie=None, host=None, headers=None):
    connection = http.client.HTTPConnection("127.0.0.1", app.port, timeout=30)
    sent = {"Host": host or f"127.0.0.1:{app.port}"}
    if token:
        sent["X-Vigie-Token"] = token
    if cookie:
        sent["Cookie"] = f"vigie_token={cookie}"
    if isinstance(body, dict):
        body = json.dumps(body).encode()
    sent.update(headers or {})
    connection.request(method, path, body=body, headers=sent)
    response = connection.getresponse()
    data = response.read()
    connection.close()
    return response, data


def events(app, path, until, timeout=30):
    """Read Server-Sent Events from ``path`` until an event named in ``until`` arrives."""
    connection = http.client.HTTPConnection("127.0.0.1", app.port, timeout=timeout)
    connection.request(
        "GET", path, headers={"Host": f"127.0.0.1:{app.port}", "Cookie": f"vigie_token={TOKEN}"}
    )
    response = connection.getresponse()
    assert response.status == 200
    assert response.getheader("Content-Type").startswith("text/event-stream")
    received, kind = [], None
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        line = response.readline().decode().rstrip("\n")
        if line.startswith("event: "):
            kind = line[7:]
        elif line.startswith("data: "):
            received.append((kind, json.loads(line[6:])))
            if kind in until:
                break
    connection.close()
    return received


# --- Who may talk to it ---------------------------------------------------------------


def test_every_request_needs_the_token(app):
    response, _ = request(app, "GET", "/", token=None)
    assert response.status == 403
    response, _ = request(app, "GET", "/api/state", token="wrong")
    assert response.status == 403
    response, body = request(app, "GET", "/api/state", token=None, cookie=TOKEN)
    assert response.status == 200
    assert json.loads(body)["version"]


def test_the_opened_url_turns_the_token_into_a_cookie(app):
    response, _ = request(app, "GET", f"/?token={TOKEN}", token=None)
    assert response.status == 303
    assert response.getheader("Location") == "/"
    cookie = response.getheader("Set-Cookie")
    assert cookie.startswith(f"vigie_token={TOKEN};")
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
    response, _ = request(app, "GET", "/?token=nope", token=None)
    assert response.status == 403


def test_changes_need_the_header_not_only_the_cookie(app):
    # A page of another site can make the browser send the cookie, never this header.
    response, _ = request(
        app, "POST", "/api/analyses", {"source": "sample"}, token=None, cookie=TOKEN
    )
    assert response.status == 403
    response, _ = request(
        app, "POST", "/api/heartbeat", {}, headers={"Origin": "https://evil.example"}
    )
    assert response.status == 403
    response, _ = request(
        app, "POST", "/api/heartbeat", {}, headers={"Origin": f"http://localhost:{app.port}"}
    )
    assert response.status == 200


@pytest.mark.parametrize(
    "host", ["evil.example", "evil.example:{port}", "127.0.0.1:1", "", "192.168.1.5:{port}"]
)
def test_other_host_names_are_refused(app, host):
    response, _ = request(app, "GET", "/api/state", host=host.format(port=app.port) or " ")
    assert response.status == 403


def test_localhost_is_accepted(app):
    response, _ = request(app, "GET", "/api/state", host=f"localhost:{app.port}")
    assert response.status == 200


def test_no_cors_headers_ever(app):
    for method, path in (("GET", "/api/state"), ("GET", "/"), ("OPTIONS", "/api/state")):
        response, _ = request(app, method, path, headers={"Origin": f"http://127.0.0.1:{app.port}"})
        assert not [
            name for name, _ in response.getheaders() if name.lower().startswith("access-control")
        ]


def test_pages_are_protected(app):
    response, body = request(app, "GET", "/")
    assert response.status == 200
    assert "frame-ancestors 'none'" in response.getheader("Content-Security-Policy")
    assert response.getheader("X-Frame-Options") == "DENY"
    assert response.getheader("Cache-Control") == "no-store"
    assert b"Drop log files or a folder here" in body


# --- What it accepts -----------------------------------------------------------------


@pytest.mark.parametrize("size", [ui.MAX_JSON + 1, 4 * 1024 * 1024])
def test_json_bodies_have_a_size_limit(app, size):
    # The 413 must reach a client that is still sending: closing on an unread body resets the
    # connection (on Windows, or anywhere once the body outgrows the socket buffers)
    for _ in range(3):
        response, _ = request(app, "POST", "/api/heartbeat", b"{" + b" " * size + b"}")
        assert response.status == 413


def test_a_body_too_big_to_read_away_is_refused_without_waiting_for_it(app):
    connection = http.client.HTTPConnection("127.0.0.1", app.port, timeout=10)
    connection.putrequest("POST", "/api/heartbeat", skip_host=True)
    connection.putheader("Host", f"127.0.0.1:{app.port}")
    connection.putheader("X-Vigie-Token", TOKEN)
    connection.putheader("Content-Length", str(ui.MAX_DRAIN + 1))
    connection.endheaders()  # and no body: reading it away would wait until the timeout
    assert connection.getresponse().status == 413
    connection.close()


def test_the_page_knows_the_upload_limit(app, monkeypatch):
    # The page refuses a bigger file itself: past MAX_DRAIN the 413 is lost in a dropped connection
    monkeypatch.setattr(ui, "MAX_UPLOAD", 12345)
    _, body = request(app, "GET", "/")
    assert b'<meta name="vigie-max-upload" content="12345">' in body


def test_uploads_have_a_size_limit(app, monkeypatch):
    monkeypatch.setattr(ui, "MAX_UPLOAD", 10)
    _, body = request(app, "POST", "/api/uploads", {})
    upload = json.loads(body)["id"]
    response, _ = request(app, "PUT", f"/api/uploads/{upload}/big.log", b"x" * 11)
    assert response.status == 413
    response, _ = request(app, "PUT", f"/api/uploads/{upload}/ok.log", b"x" * 10)
    assert response.status == 201


def test_bodies_need_a_length(app):
    connection = http.client.HTTPConnection("127.0.0.1", app.port, timeout=10)
    connection.putrequest("POST", "/api/heartbeat", skip_host=True)
    connection.putheader("Host", f"127.0.0.1:{app.port}")
    connection.putheader("X-Vigie-Token", TOKEN)
    connection.putheader("Transfer-Encoding", "chunked")
    connection.endheaders()
    connection.send(b"2\r\n{}\r\n0\r\n\r\n")
    assert connection.getresponse().status == 411
    connection.close()


@pytest.mark.parametrize(
    "name", ["../escape.log", "a/../../escape.log", "%2E%2E/escape.log", "C:x.log"]
)
def test_uploads_stay_in_their_folder(app, name):
    _, body = request(app, "POST", "/api/uploads", {})
    upload = json.loads(body)["id"]
    response, _ = request(app, "PUT", f"/api/uploads/{upload}/{name}", b"data")
    assert response.status == 400
    assert not list(app.temp_root.parent.glob("escape.log"))
    assert not list(app.temp_root.glob("escape.log"))


@pytest.mark.parametrize(
    ("first", "path", "status"),
    [
        (None, "{upload}/C:x.log", 400),
        ("{upload}/a", "{upload}/a/b.log", 400),
        ("{upload}/a/b.log", "{upload}/a", 400),
        (None, "{upload}/" + "x" * 300, 400),
        (None, "zzz/a.log", 404),
        (None, "{unknown}/a.log", 404),
    ],
)
def test_a_refused_upload_gets_its_answer(app, first, path, status):
    # Refused after the size check, the body is read away all the same so the error is not
    # lost in a reset connection
    _, body = request(app, "POST", "/api/uploads", {})
    ids = {"upload": json.loads(body)["id"], "unknown": "0" * 24}
    if first:
        assert request(app, "PUT", "/api/uploads/" + first.format(**ids), b"x")[0].status == 201
    for _ in range(3):
        response, _ = request(app, "PUT", "/api/uploads/" + path.format(**ids), b"x" * 4 * 2**20)
        assert response.status == status


def test_an_upload_past_the_file_count_gets_its_answer(app, monkeypatch):
    monkeypatch.setattr(ui, "MAX_UPLOAD_FILES", 0)
    _, body = request(app, "POST", "/api/uploads", {})
    url = f"/api/uploads/{json.loads(body)['id']}/a.log"
    assert request(app, "PUT", url, b"x" * 4 * 2**20)[0].status == 413


def test_reports_are_only_those_the_app_wrote(app, tmp_path):
    for path in (
        "/reports/../../etc/passwd",
        "/reports/20260101-000000-abcdef/report.html",
        "/reports/x/report.html",
        "/api/reports/x/open",
    ):
        method = "POST" if path.startswith("/api") else "GET"
        response, _ = request(app, method, path, {} if method == "POST" else None)
        assert response.status == 404, path


def test_unknown_sources_and_missing_paths(app, tmp_path):
    response, body = request(
        app, "POST", "/api/analyses", {"source": "path", "path": str(tmp_path / "no")}
    )
    assert response.status == 400 and "nothing at" in json.loads(body)["error"]
    response, _ = request(app, "POST", "/api/analyses", {"source": "url", "path": "http://x"})
    assert response.status == 400
    response, _ = request(app, "POST", "/api/analyses", {"source": "upload", "upload": "f" * 24})
    assert response.status == 404


# --- A full analysis through the API ---------------------------------------------------


def test_sample_analysis_end_to_end(app):
    response, body = request(app, "POST", "/api/analyses", {"source": "sample"})
    assert response.status == 201
    job = json.loads(body)["id"]
    received = events(app, f"/api/analyses/{job}/events", until={"done", "failed"})
    kinds = [kind for kind, _ in received]
    assert kinds[-1] == "done", received[-1]
    stages = [data["stage"] for kind, data in received if kind == "progress"]
    assert {"start", "file", "parsed", "match", "done"} <= set(stages)
    entry = received[-1][1]
    assert entry["label"] == "Sample logs"
    assert entry["events"] == 90 and entry["files"] == 9
    assert entry["counts"]["high"] > 0
    # The report is served, and listed in the recent analyses.
    response, html = request(
        app, "GET", f"/reports/{entry['id']}/report.html", token=None, cookie=TOKEN
    )
    assert response.status == 200
    assert b"LLM Prompt Injection In Retrieved Content Or Tool Result" in html
    assert b"Poisoned MCP Tool Description" in html
    assert b"<h2>OWASP Top 10</h2>" in html and b"<dt>OWASP</dt>" in html
    assert response.getheader("X-Frame-Options") == "SAMEORIGIN"
    _, state = request(app, "GET", "/api/state")
    assert [e["id"] for e in json.loads(state)["recent"]] == [entry["id"]]
    # Open in the browser, and show in the folder, act on that file only.
    request(app, "POST", f"/api/reports/{entry['id']}/open", {})
    request(app, "POST", f"/api/reports/{entry['id']}/reveal", {})
    report = app.reports_dir / entry["id"] / "report.html"
    assert app.opened == [report.resolve().as_uri()]
    assert app.revealed == [report]
    # A late page gets the whole story again.
    assert events(app, f"/api/analyses/{job}/events", until={"done"})[-1][0] == "done"
    response, _ = request(app, "DELETE", f"/api/reports/{entry['id']}")
    assert response.status == 200 and not report.exists()


def test_uploaded_files_are_analyzed_then_deleted(app):
    _, body = request(app, "POST", "/api/uploads", {})
    upload = json.loads(body)["id"]
    data = (FIXTURES / "agentlog" / "agent_tool_abuse.jsonl").read_bytes()
    response, _ = request(
        app,
        "PUT",
        f"/api/uploads/{upload}/agent/tool%20abuse.jsonl",
        data,
        headers={"X-Last-Modified": "1700000000000"},
    )
    assert response.status == 201
    folder = app.temp_root / upload
    assert (folder / "agent" / "tool abuse.jsonl").read_bytes() == data
    assert int((folder / "agent" / "tool abuse.jsonl").stat().st_mtime) == 1700000000
    _, body = request(
        app, "POST", "/api/analyses", {"source": "upload", "upload": upload, "label": "agent"}
    )
    job = json.loads(body)["id"]
    entry = events(app, f"/api/analyses/{job}/events", until={"done", "failed"})[-1][1]
    assert entry["label"] == "agent" and entry["alerts"] >= 3
    assert not folder.exists()


def test_local_path_analysis(app):
    _, body = request(
        app,
        "POST",
        "/api/analyses",
        {"source": "path", "path": str(FIXTURES / "authlog" / "auth.log")},
    )
    job = json.loads(body)["id"]
    entry = events(app, f"/api/analyses/{job}/events", until={"done", "failed"})[-1][1]
    assert entry["kind"] == "path" and entry["events"] == 29


def test_watch_streams_alerts(app, tmp_path):
    log = tmp_path / "agent.jsonl"
    shutil.copy(FIXTURES / "agentlog" / "agent_benign.jsonl", log)
    response, body = request(app, "POST", "/api/watches", {"path": str(tmp_path)})
    assert response.status == 201, body
    watch = json.loads(body)
    assert watch["files"] == [str(log)]

    def write_later():
        time.sleep(0.5)
        with log.open("a", encoding="utf-8") as handle:
            handle.write((FIXTURES / "agentlog" / "agent_jailbreak.jsonl").read_text("utf-8"))

    threading.Thread(target=write_later).start()
    received = events(app, f"/api/watches/{watch['id']}/events", until={"alert"})
    alert = received[-1][1]
    assert alert["title"] == "LLM Jailbreak Attempt" and alert["techniques"] == ["AML.T0054"]
    assert any(kind == "status" for kind, _ in received)
    response, _ = request(
        app, "GET", f"/watches/{watch['id']}/report.html", token=None, cookie=TOKEN
    )
    assert response.status == 200
    _, body = request(app, "POST", f"/api/watches/{watch['id']}/pause", {"paused": True})
    assert json.loads(body) == {"paused": True}
    request(app, "POST", f"/api/watches/{watch['id']}/stop", {})
    assert events(app, f"/api/watches/{watch['id']}/events", until={"stopped"})[-1][0] == "stopped"


def test_watch_needs_a_followable_log(app, tmp_path):
    (tmp_path / "notes.txt").write_text("hello", encoding="utf-8")
    response, body = request(app, "POST", "/api/watches", {"path": str(tmp_path)})
    assert response.status == 400 and "no log Vigie can follow" in json.loads(body)["error"]


# --- Lifetime ---------------------------------------------------------------------------


def test_stops_when_no_page_checks_in(tmp_path):
    app = App(reports_dir=tmp_path, idle_timeout=0.05)
    assert not app.idle()
    time.sleep(0.1)
    assert app.idle()
    app.touch()
    assert not app.idle()
    app.close()


def test_uploads_are_deleted_on_exit(tmp_path):
    app = App(reports_dir=tmp_path)
    upload = app.uploads.new()
    target = app.uploads.add_file(upload, "auth.log")
    target.write_text("x", encoding="utf-8")
    app.close()
    assert not app.temp_root.exists()


def test_serve_stops_when_idle(monkeypatch, tmp_path):
    monkeypatch.setenv("VIGIE_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(ui.time, "sleep", lambda seconds: None)
    said = []
    assert ui.serve(port=0, open_browser=False, say=said.append, idle_timeout=0) == 0
    assert said[0].startswith("Vigie is running at http://127.0.0.1:")
    assert said[-1] == "Vigie stopped."


def test_binding_needs_no_name_lookup(monkeypatch, tmp_path):
    # A reverse DNS lookup of 127.0.0.1 can take half a minute on some networks.
    def no_lookup(*_args):
        raise AssertionError("the server looked up a host name")

    monkeypatch.setattr(socket, "getfqdn", no_lookup)
    app = App(reports_dir=tmp_path)
    server = make_server(app, 0)
    try:
        assert server.server_name == "127.0.0.1"
        assert server.server_port == app.port > 0
    finally:
        server.server_close()
        app.close()


def test_serve_does_not_wait_for_the_browser(monkeypatch, tmp_path):
    monkeypatch.setenv("VIGIE_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(ui.time, "sleep", lambda seconds: None)
    called, release, opened = threading.Event(), threading.Event(), []

    def slow_browser(url):
        opened.append(url)
        called.set()
        release.wait(10)

    class SlowBrowserApp(ui.App):
        def __init__(self, **kwargs):
            super().__init__(opener=slow_browser, **kwargs)

    monkeypatch.setattr(ui, "App", SlowBrowserApp)
    run = threading.Thread(
        target=ui.serve, kwargs={"port": 0, "say": lambda _text: None, "idle_timeout": 0}
    )
    run.start()
    try:
        run.join(5)
        assert not run.is_alive()  # the app served and stopped while the browser was starting
        assert called.wait(5)
        assert opened[0].startswith("http://127.0.0.1:")
    finally:
        release.set()


def test_recent_keeps_the_latest(tmp_path, monkeypatch):
    monkeypatch.setattr(ui, "RECENT_LIMIT", 2)
    recent = Recent(tmp_path)
    for n in range(3):
        report_id = f"20261029-10000{n}-abcdef"
        (tmp_path / report_id).mkdir()
        recent.add({"id": report_id})
    assert [e["id"] for e in recent.load()] == ["20261029-100002-abcdef", "20261029-100001-abcdef"]
    assert not (tmp_path / "20261029-100000-abcdef").exists()
    (tmp_path / "recent.json").write_text("not json", encoding="utf-8")
    assert recent.load() == []
