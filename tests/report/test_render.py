import json
import os
from html.parser import HTMLParser
from pathlib import Path

import pytest

from vigie.analysis import analyze
from vigie.report.builder import build_report
from vigie.report.render import (
    md,
    render_html,
    render_json,
    render_markdown,
    rule_path,
    timestamp,
)

from .conftest import GENERATED_AT

GOLDEN = Path(__file__).parent / "expected_auth_report.md"


@pytest.fixture
def auth_report(analysis_of):
    return build_report(analysis_of("authlog/auth.log"), generated_at=GENERATED_AT)


def test_markdown_matches_the_reference_report(auth_report):
    """Set VIGIE_UPDATE_GOLDEN=1 to rewrite the reference after a deliberate change."""
    rendered = render_markdown(auth_report)
    if os.environ.get("VIGIE_UPDATE_GOLDEN"):
        GOLDEN.write_text(rendered, encoding="utf-8")
    assert rendered == GOLDEN.read_text(encoding="utf-8")


class Tags(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


def test_html_is_self_contained(auth_report):
    html = render_html(auth_report)
    parser = Tags()
    parser.feed(html)
    names = [tag for tag, _ in parser.tags]
    assert names[0] == "html"
    assert "script" not in names
    assert "link" not in names
    assert "img" not in names
    assert names.count("details") == auth_report.alert_count
    # Only links to ATT&CK pages leave the file.
    hrefs = [attrs["href"] for tag, attrs in parser.tags if tag == "a"]
    assert hrefs and all(h.startswith("https://attack.mitre.org/") for h in hrefs)


def test_json_is_complete(auth_report):
    data = json.loads(render_json(auth_report))
    assert data["alert_count"] == auth_report.alert_count
    assert data["generated_at"] == "2026-09-28T12:00:00Z"
    alert = data["alerts"][0]
    assert alert["rule"]["title"] == "SSH Login After Brute Force"
    assert alert["attack"]["techniques"][0]["id"] == "T1078.003"
    assert alert["first_seen"].endswith("Z")
    # No absolute path of the install (or of the user's home) in a shareable report.
    assert alert["rule"]["path"] == "vigie/rules/linux/lnx_ssh_login_after_bruteforce.yml"


def test_rule_path_hides_the_folder(tmp_path):
    assert rule_path(str(tmp_path / "custom" / "my_rule.yml")) == "my_rule.yml"
    assert rule_path("") == ""


HOSTILE = "<script>alert(1)</script>|**x**"


@pytest.fixture
def hostile_report(tmp_path):
    """A SYNTHETIC auth.log whose user names try to inject markup into the report."""
    lines = [
        f"Mar 10 09:00:{i:02d} web01 sshd[1]: Failed password for invalid user {HOSTILE} "
        f"from 203.0.113.9 port {4000 + i} ssh2"
        for i in range(10)
    ]
    (tmp_path / "auth.log").write_text("\n".join(lines) + "\n")
    return build_report(analyze(tmp_path, year=2024), generated_at=GENERATED_AT)


def test_html_escapes_log_content(hostile_report):
    html = render_html(hostile_report)
    assert "<script>alert(1)" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_markdown_escapes_log_content(hostile_report):
    text = render_markdown(hostile_report)
    assert "<script>" not in text
    assert "\\<script\\>alert(1)\\</script\\>\\|\\*\\*x\\*\\*" in text


def test_md_filter():
    assert md("a|b") == "a\\|b"
    assert md("C:\\Windows\\x.exe") == "C:\\\\Windows\\\\x.exe"
    assert md("two\nlines  here") == "two lines here"
    assert md("[link](x) `code` #h _i_ {b}") == "\\[link\\](x) \\`code\\` \\#h \\_i\\_ \\{b\\}"


def test_timestamp_filter():
    assert timestamp(None) == "-"
    assert timestamp(GENERATED_AT) == "2026-09-28 12:00:00Z"


def test_empty_report_renders(analysis_of):
    report = build_report(analysis_of(), generated_at=GENERATED_AT)
    assert "No alert at level low or above." in render_markdown(report)
    assert "No alert at level low or above." in render_html(report)
    assert json.loads(render_json(report))["alerts"] == []
