"""Check a zipped app as people download it: what is inside, and that it runs once unzipped.

    python packaging/check_zip.py Vigie-windows.zip
    python packaging/check_zip.py Vigie-macos.zip

The macOS zip is unzipped with ditto, as the Finder does, which keeps the
symbolic links and the signature of the bundle; its signature is checked again.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import plistlib
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

import vigie

LICENSES = ["LICENSE", "THIRD_PARTY_NOTICES.md", "python-license/LICENSE.txt"]
WINDOWS = {
    "program": "Vigie/Vigie.exe",
    "needs": [
        *(f"Vigie/_internal/{name}" for name in LICENSES),
        "Vigie/_internal/vigie/rules/LICENSE.DRL-1.1.md",
        "Vigie/_internal/tzdata/zoneinfo/Europe/Paris",
    ],
}
MACOS = {
    "program": "Vigie.app/Contents/MacOS/Vigie",
    "needs": [
        "Vigie.app/Contents/Info.plist",
        "Vigie.app/Contents/Resources/vigie.icns",
        *(f"Vigie.app/Contents/Resources/{name}" for name in LICENSES),
        "Vigie.app/Contents/Resources/vigie/rules/LICENSE.DRL-1.1.md",
    ],
}


class Failed(Exception):
    pass


def note(title: str, message: str) -> None:
    """A line of the log, and an annotation of the workflow run on GitHub."""
    print(f"{title}: {message}", flush=True)
    if os.environ.get("GITHUB_ACTIONS") == "true":
        text = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print(f"::notice title={title}::{text}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("zip", type=Path)
    args = parser.parse_args()
    try:
        check(args.zip.resolve())
    except Failed as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        return 1
    return 0


def check(archive: Path) -> None:
    with zipfile.ZipFile(archive) as zipped:
        entries = zipped.infolist()
        names = {entry.filename for entry in entries}
        layout = MACOS if MACOS["program"] in names else WINDOWS
        missing = [name for name in [layout["program"], *layout["needs"]] if name not in names]
        if missing:
            raise Failed(f"missing from {archive.name}: {', '.join(missing)}")
        links = sum(stat.S_ISLNK(entry.external_attr >> 16) for entry in entries)
        size = sum(entry.file_size for entry in entries)
        depth = 3 if layout is MACOS else 2
        parts = [name.rstrip("/").split("/") for name in names]
        tops = sorted({"/".join(part[:depth]) for part in parts if len(part) >= depth})
        note(
            f"{archive.name} contents",
            f"{len(entries)} entries ({links} symbolic links), {size / 2**20:.1f} MB unzipped, "
            f"{archive.stat().st_size / 2**20:.1f} MB zipped, SHA-256 "
            f"{hashlib.sha256(archive.read_bytes()).hexdigest()}. Top: {', '.join(tops[:12])}",
        )
        if layout is MACOS:
            info = plistlib.loads(zipped.read("Vigie.app/Contents/Info.plist"))
            check_info(info)
            if links == 0:
                raise Failed("the bundle lost its symbolic links in the zip")
    with tempfile.TemporaryDirectory(prefix="vigie-zip-") as folder:
        work = Path(folder)
        unzipped = work / "unzipped"
        if layout is MACOS:
            subprocess.run(["ditto", "-x", "-k", str(archive), str(unzipped)], check=True)
            app = unzipped / "Vigie.app"
            result = subprocess.run(
                ["codesign", "--verify", "--deep", "--strict", str(app)],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                raise Failed(f"the unzipped app's signature: {result.stderr.strip()}")
            note("Unzipped Vigie.app", "codesign --verify --deep --strict passes")
        else:
            with zipfile.ZipFile(archive) as zipped:
                zipped.extractall(unzipped)
        program = unzipped / layout["program"]
        out = work / "out"
        code = subprocess.run(
            [str(program), "demo", "--no-open", "-o", str(out)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            env={**os.environ, "VIGIE_DATA_DIR": str(work / "data")},
            timeout=300,
            check=False,
        ).returncode
        report = out / "report.html"
        if code != 0 or not report.is_file():
            raise Failed(f"the unzipped program: exit code {code}, report: {report.is_file()}")
        note("Unzipped program", f"{layout['program']} demo wrote report.html")


def check_info(info: dict) -> None:
    keys = [
        "CFBundleName",
        "CFBundleDisplayName",
        "CFBundleIdentifier",
        "CFBundleExecutable",
        "CFBundleIconFile",
        "CFBundleShortVersionString",
        "CFBundleVersion",
        "LSMinimumSystemVersion",
        "LSUIElement",
    ]
    note("Info.plist", ", ".join(f"{key}={info.get(key)!r}" for key in keys))
    expected = {
        "CFBundleName": "Vigie",
        "CFBundleExecutable": "Vigie",
        "CFBundleIconFile": "vigie.icns",
        "CFBundleShortVersionString": vigie.__version__,
        "LSMinimumSystemVersion": "11.0",
        "LSUIElement": True,
    }
    wrong = [key for key, value in expected.items() if info.get(key) != value]
    if wrong:
        raise Failed(f"unexpected Info.plist values: {', '.join(wrong)}")


if __name__ == "__main__":
    raise SystemExit(main())
