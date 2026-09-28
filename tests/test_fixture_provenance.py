"""The provenance tables in tests/fixtures match the files next to them.

Checking excerpts against the upstream datasets needs network access, so it is
done by hand; this test catches files replaced, edited or added without their
README entry.
"""

import hashlib
import re
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"


def test_evtx_samples_match_their_readme():
    table = dict(
        re.findall(
            r"^\| `([^`]+\.evtx)` \| `[^`]+` \| `([0-9a-f]{64})` \|$",
            (FIXTURES / "evtx" / "README.md").read_text(encoding="utf-8"),
            re.MULTILINE,
        )
    )
    files = {path.name: path for path in (FIXTURES / "evtx").glob("*.evtx")}
    assert table.keys() == files.keys()
    for name, digest in table.items():
        assert hashlib.sha256(files[name].read_bytes()).hexdigest() == digest, name


def test_otrf_excerpts_match_their_readme():
    table = dict(
        re.findall(
            r"^\| `([^`]+_excerpt\.json)` \| `[^`]+\.zip` \| `[^`]+\.json` \| ([0-9, ]+) \|$",
            (FIXTURES / "README.md").read_text(encoding="utf-8"),
            re.MULTILINE,
        )
    )
    files = {path.name: path for path in (FIXTURES / "winjson").glob("*_excerpt.json")}
    assert table.keys() == files.keys()
    for name, lines in table.items():
        kept = [int(number) for number in lines.split(",")]
        assert kept == sorted(set(kept)), name
        assert len(files[name].read_bytes().splitlines()) == len(kept), name


def test_synthetic_auth_logs_are_listed():
    readme = (FIXTURES / "README.md").read_text(encoding="utf-8")
    listed = set(re.findall(r"^\| `([^`/]+\.log)` \|", readme, re.MULTILINE))
    assert listed == {path.name for path in (FIXTURES / "authlog").glob("*.log")}
