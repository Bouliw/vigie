"""Smoke test of the standalone program PyInstaller built, run as a user and a script would.

    python packaging/smoke_test.py dist/Vigie/Vigie.exe --shortcut
    python packaging/smoke_test.py dist/Vigie.app/Contents/MacOS/Vigie --double-click dist/Vigie.app

It runs the demo, starts the app and analyzes the sample logs through it as the
page does. --shortcut checks the desktop icon the first run adds on Windows;
--double-click opens the macOS app twice, the way the Finder does.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "authlog"
ADDRESS = re.compile(r"Vigie is running at (http://127\.0\.0\.1:\d+)/\?token=([\w-]+)")
PREFERRED_PORT = 47731


class Failed(Exception):
    pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("program", type=Path, help="the built program")
    parser.add_argument("--shortcut", action="store_true", help="Windows: check the first run")
    parser.add_argument("--double-click", type=Path, metavar="APP", help="macOS: the app bundle")
    args = parser.parse_args()
    program = args.program.resolve()
    with tempfile.TemporaryDirectory(prefix="vigie-smoke-") as folder:
        work = Path(folder)
        env = {
            **os.environ,
            "VIGIE_DATA_DIR": str(work / "data"),
            "VIGIE_CONFIG_DIR": str(work / "config"),
        }
        try:
            check_demo(program, work, env)
            check_time_zone(program, work, env)
            check_app(program, work, env)
            if args.shortcut:
                check_first_run_icon(program, work, env)
            if args.double_click:
                check_double_click(args.double_click.resolve())
        except Failed as exc:
            print(f"FAILED: {exc}", file=sys.stderr)
            return 1
    print("All checks passed.")
    return 0


def step(text: str) -> None:
    print(f"\n== {text}", flush=True)


def note(title: str, message: str) -> None:
    """A line of the log, and an annotation of the workflow run on GitHub."""
    print(f"{title}: {message}", flush=True)
    if os.environ.get("GITHUB_ACTIONS") == "true":
        text = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print(f"::notice title={title}::{text}", flush=True)


def output(work: Path, env: dict[str, str]) -> str:
    """What the program printed: its standard output, or app.log when it has no console."""
    parts = []
    for path in (work / "output.txt", Path(env["VIGIE_DATA_DIR"]) / "app.log"):
        if path.is_file():
            parts.append(path.read_text(encoding="utf-8", errors="replace"))
    return "".join(parts)


def run(program: Path, args: list[str], work: Path, env: dict[str, str]) -> tuple[int, str]:
    (Path(env["VIGIE_DATA_DIR"]) / "app.log").unlink(missing_ok=True)
    with (work / "output.txt").open("w", encoding="utf-8") as handle:
        code = subprocess.run(
            [str(program), *args],
            stdin=subprocess.DEVNULL,
            stdout=handle,
            stderr=subprocess.STDOUT,
            env=env,
            timeout=300,
            check=False,
        ).returncode
    text = output(work, env)
    print(f"$ {program.name} {' '.join(args)}  (exit code {code})\n{text}", flush=True)
    return code, text


def wait_for(what: str, test: Callable[[], object], timeout: float = 60) -> object:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = test()
        if result:
            return result
        time.sleep(0.5)
    raise Failed(f"timed out waiting for {what}")


def check_demo(program: Path, work: Path, env: dict[str, str]) -> None:
    step("the demo writes its report")
    code, _ = run(program, ["demo", "--no-open", "-o", str(work / "demo")], work, env)
    report = work / "demo" / "report.html"
    if code != 0 or not report.is_file():
        raise Failed(f"vigie demo: exit code {code}, report written: {report.is_file()}")
    html = report.read_text(encoding="utf-8")
    if "AI Agent" not in html or len(html) < 50_000:
        raise Failed("the demo report has no alerts")
    note("Demo", f"report.html of {len(html):,} characters")


def check_time_zone(program: Path, work: Path, env: dict[str, str]) -> None:
    step("an analysis in another time zone than UTC (Windows needs the bundled tzdata)")
    out = work / "tz"
    args = ["analyze", str(FIXTURES), "--tz", "Europe/Berlin", "--year", "2024"]
    code, _ = run(program, [*args, "--format", "json", "-o", str(out)], work, env)
    report = out / "report.json"
    if code != 0 or not report.is_file():
        raise Failed(f"vigie analyze --tz Europe/Berlin: exit code {code}")
    events = json.loads(report.read_text(encoding="utf-8"))["event_count"]
    note("Time zone", f"analyze --tz Europe/Berlin read {events} events")


def request(url: str, token: str, data: dict | None = None) -> tuple[int, bytes]:
    headers = {"Cookie": f"vigie_token={token}"}
    body = None
    if data is not None:
        body = json.dumps(data).encode()
        headers.update({"Content-Type": "application/json", "X-Vigie-Token": token})
    try:
        with urllib.request.urlopen(urllib.request.Request(url, body, headers), timeout=60) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def check_app(program: Path, work: Path, env: dict[str, str]) -> None:
    step("the app starts, serves its page and analyzes the sample logs")
    (Path(env["VIGIE_DATA_DIR"]) / "app.log").unlink(missing_ok=True)
    with (work / "output.txt").open("w", encoding="utf-8") as handle:
        process = subprocess.Popen(
            [str(program), "ui", "--no-open"],
            stdin=subprocess.DEVNULL,
            stdout=handle,
            stderr=subprocess.STDOUT,
            env=env,
        )
    try:

        def started() -> re.Match[str] | None:
            if process.poll() is not None:
                raise Failed(f"the app stopped (exit code {process.returncode})")
            return ADDRESS.search(output(work, env))

        found = wait_for("the app's address", started)
        assert isinstance(found, re.Match)
        base, token = found.group(1), found.group(2)
        print(f"The app answers at {base}")
        status, page = request(base + "/", token)
        if status != 200 or b"<title>Vigie" not in page:
            raise Failed(f"the app page: HTTP {status}")
        status, body = request(base + "/api/analyses", token, {"source": "sample"})
        if status != 201:
            raise Failed(f"starting an analysis: HTTP {status} {body!r}")
        analysis = json.loads(body)["id"]
        status, events = request(f"{base}/api/analyses/{analysis}/events", token)
        if status != 200 or b"event: done" not in events:
            raise Failed(f"the analysis did not finish: {events[-500:]!r}")
        status, report = request(f"{base}/reports/{analysis}/report.html", token)
        if status != 200 or b"AI Agent" not in report:
            raise Failed(f"the report of the analysis: HTTP {status}")
        note("App", f"page served at {base}, sample analysis report of {len(report):,} bytes")
    finally:
        process.terminate()
        process.wait(timeout=30)
    print(output(work, env))


def check_first_run_icon(program: Path, work: Path, env: dict[str, str]) -> None:
    step("the first run adds the desktop icon, once")
    env = {name: value for name, value in env.items() if name != "CI"}
    env["VIGIE_CONFIG_DIR"] = str(work / "config-first-run")
    desktop = Path(powershell("[Environment]::GetFolderPath('Desktop')"))
    link = desktop / "Vigie.lnk"
    if link.exists():
        raise Failed(f"{link} is there before the first run")
    code, text = run(program, ["rules"], work, env)
    if code != 0 or not link.is_file():
        raise Failed(f"no icon after the first run: {link}")
    script = (
        f"$l = (New-Object -ComObject WScript.Shell).CreateShortcut('{link}'); "
        "$l.TargetPath; $l.Arguments; $l.IconLocation"
    )
    target, arguments, icon = powershell(script).splitlines()
    note("First run", f"{link} opens {target} {arguments} (icon {icon})")
    same = Path(target) == program and icon.lower().startswith(str(program).lower())
    if not same or arguments != "ui":
        raise Failed("the icon does not open this program")
    if "Vigie added an icon" not in text:
        raise Failed("the first run did not say it added the icon")
    run(program, ["shortcut", "--remove"], work, env)
    if link.exists():
        raise Failed("vigie shortcut --remove left the icon")
    run(program, ["rules"], work, env)
    if link.exists():
        raise Failed("the icon came back after it was removed")


def powershell(script: str) -> str:
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    return result.stdout.strip()


def check_double_click(app: Path) -> None:
    step("double-clicking the app opens it, every time")
    pattern = f"{app}/Contents/MacOS/Vigie ui"

    def servers() -> list[str]:
        found = subprocess.run(["pgrep", "-f", pattern], capture_output=True, text=True)
        return found.stdout.split()

    if servers():
        raise Failed("an app server is already running")
    started = time.monotonic()
    try:
        subprocess.run(["open", str(app)], check=True, timeout=60)
        wait_for("the first app server", lambda: len(servers()) == 1)
        first = time.monotonic() - started

        def answers() -> bool:
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{PREFERRED_PORT}/", timeout=5)
            except urllib.error.HTTPError as exc:
                return exc.code == 403  # it wants its token: that is Vigie
            except OSError:
                return False
            return False

        wait_for("the app to answer", answers)
        answered = time.monotonic() - started
        subprocess.run(["open", str(app)], check=True, timeout=60)
        wait_for("a second app server", lambda: len(servers()) == 2)
        note(
            "Double-clicks",
            f"first server after {first:.1f} s, answering on port {PREFERRED_PORT} after "
            f"{answered:.1f} s; second double-click, second server after "
            f"{time.monotonic() - started:.1f} s",
        )
    finally:
        for pid in servers():
            os.kill(int(pid), signal.SIGTERM)
    log = Path.home() / "Library" / "Application Support" / "Vigie" / "app.log"
    if log.is_file():
        print(log.read_text(encoding="utf-8", errors="replace"))


if __name__ == "__main__":
    raise SystemExit(main())
