"""The interactive HTML report: controls, data attributes, valid markup, no-JS and live modes."""

import json
import re
import shutil
import subprocess
from html.parser import HTMLParser

import pytest

from vigie.analysis import analyze
from vigie.report.builder import build_report
from vigie.report.render import duration, html_view, number, render_html, safe_url
from vigie.rules import RULES_DIR

from .conftest import FIXTURES, GENERATED_AT

VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "wbr"}
# SVG elements the template writes self-closed.
SELF_CLOSED = {"path", "circle", "rect", "use"}


class Page(HTMLParser):
    """Collects tags and checks that every element is closed, in order."""

    def __init__(self):
        super().__init__()
        self.tags = []
        self.stack = []
        self.errors = []
        self.scripts = []
        self._script = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.tags.append((tag, attrs))
        if tag == "script":
            self._script = (attrs, [])
        if tag not in VOID:
            self.stack.append(tag)

    def handle_startendtag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))
        if tag not in VOID and tag not in SELF_CLOSED:
            self.errors.append(f"self-closed <{tag}/>")

    def handle_endtag(self, tag):
        if tag == "script" and self._script:
            self.scripts.append((self._script[0], "".join(self._script[1])))
            self._script = None
        if not self.stack or self.stack[-1] != tag:
            self.errors.append(f"</{tag}> closes <{self.stack[-1] if self.stack else None}>")
            return
        self.stack.pop()

    def handle_data(self, data):
        if self._script:
            self._script[1].append(data)

    def find(self, tag=None, class_=None, **attrs):
        """Elements by tag, one of their classes, and attributes (data_help= is data-help=)."""
        found = []
        for name, values in self.tags:
            if tag is not None and name != tag:
                continue
            if class_ is not None and class_ not in (values.get("class") or "").split():
                continue
            if all(values.get(key.replace("_", "-")) == value for key, value in attrs.items()):
                found.append(values)
        return found


def parse(html):
    page = Page()
    page.feed(html)
    page.close()
    return page


@pytest.fixture
def mixed_report(atlas_rule):
    analysis = analyze(
        FIXTURES / "authlog" / "auth.log", rules=[atlas_rule, RULES_DIR / "linux"], year=2024
    )
    return build_report(analysis, generated_at=GENERATED_AT)


@pytest.fixture
def ai_report(analysis_of):
    analysis = analysis_of(
        "agentlog/agent_indirect_injection.jsonl", "agentlog/agent_data_leak.jsonl"
    )
    return build_report(analysis, generated_at=GENERATED_AT)


@pytest.fixture
def auth_report(analysis_of):
    return build_report(analysis_of("authlog/auth.log"), generated_at=GENERATED_AT)


def test_markup_is_well_formed_with_unique_ids(auth_report, ai_report, mixed_report):
    for report in (auth_report, ai_report, mixed_report):
        page = parse(render_html(report))
        assert page.errors == []
        assert page.stack == []
        ids = [attrs["id"] for _, attrs in page.tags if "id" in attrs]
        assert len(ids) == len(set(ids))
        # Every aria-controls and in-page link points to an element of the page.
        targets = {attrs["aria-controls"] for _, attrs in page.tags if "aria-controls" in attrs}
        links = {
            attrs["href"][1:]
            for tag, attrs in page.tags
            if tag in ("a", "use") and attrs.get("href", "").startswith("#")
        }
        assert targets | links <= set(ids) | {"top"}


def test_toolbar_controls(auth_report):
    page = parse(render_html(auth_report))
    (search,) = page.find("input", id="q")
    assert search["type"] == "search" and search["aria-label"] == "Search alerts"
    chips = page.find("button", class_="chip-sev")
    assert [c["data-level"] for c in chips] == list(auth_report.level_counts)
    assert all(c["aria-pressed"] == "false" for c in chips)
    # A level without alerts cannot be picked.
    assert all(("disabled" in c) == (not auth_report.level_counts[c["data-level"]]) for c in chips)
    (expand,) = page.find("button", id="expand-all")
    assert expand["aria-pressed"] == "false"
    (count,) = page.find("output", id="count")
    assert count["role"] == "status" and count["aria-live"] == "polite"
    assert page.find(id="empty") and page.find(id="popover") and page.find(id="theme")
    # The toolbar needs JavaScript: without it, it is hidden and every card is open.
    (toolbar,) = page.find(id="toolbar")
    assert "js-only" in toolbar["class"].split()
    assert page.find("html")[0]["class"] == "no-js"
    # No ATT&CK / ATLAS switch when the alerts map to ATT&CK only.
    assert not [b for b in page.find("button") if "data-fw" in b]


def test_every_alert_card_carries_its_filter_data(auth_report):
    html = render_html(auth_report)
    page = parse(html)
    cards = page.find("article", class_="card")
    assert len(cards) == auth_report.alert_count
    for card, alert in zip(cards, auth_report.alerts, strict=True):
        assert card["data-level"] == alert.rule.level
        assert card["data-rule"] == alert.rule.id
        assert card["data-techniques"].split() == [t.id for t in alert.attack.techniques]
        assert card["data-tactics"].split() == [t.id for t in alert.attack.tactics]
        assert card["data-frameworks"] == "attack"
        assert card["data-hosts"].split() == list(alert.hosts)
        assert f"sev-{alert.rule.level}" in card["class"].split()
        (why,) = [
            a for a in page.find("button", class_="why") if a["aria-controls"] == card["id"] + "-b"
        ]
        assert why["aria-expanded"] == "false"


def test_explanations_are_in_the_page(auth_report):
    page = parse(render_html(auth_report))
    (data,) = [text for attrs, text in page.scripts if attrs.get("id") == "vigie-data"]
    data = json.loads(data)
    brute = data["techniques"]["T1110.001"]
    assert brute["name"] == "Brute Force: Password Guessing"
    assert brute["summary"].startswith("Adversaries with no prior knowledge")
    assert brute["tactics"] == ["Credential Access"]
    assert data["tactics"]["TA0006"]["summary"] == (
        "The adversary is trying to steal account names and passwords."
    )
    assert set(data["help"]) >= {"high", "events", "files", "rules", "alerts"}
    # Chips link to the technique's entry, which explains it without JavaScript too.
    chips = page.find("a", class_="chip")
    assert chips and all(c["href"] == "#t-" + c["data-technique"].replace(".", "-") for c in chips)
    html = render_html(auth_report)
    assert "Adversaries with no prior knowledge of legitimate credentials" in html
    assert page.find("button", data_help="high")


def test_coverage_strip_lists_every_tactic(auth_report):
    page = parse(render_html(auth_report))
    cells = page.find("button", class_="cell")
    assert [c["data-tactic"] for c in cells] == [t.tactic.id for t in auth_report.tactics]
    view = html_view(auth_report)
    (strip,) = view["strips"]
    assert len(strip["cells"]) == 15  # every ATT&CK tactic, seen or not
    assert max(cell["heat"] for cell in strip["cells"]) == 4


def test_mixed_report_has_the_framework_switch(mixed_report):
    page = parse(render_html(mixed_report))
    assert [b["data-fw"] for b in page.find("button") if "data-fw" in b] == [
        "all",
        "attack",
        "atlas",
    ]
    frameworks = {c["data-frameworks"] for c in page.find("article", class_="card")}
    assert frameworks == {"attack", "atlas"}
    assert [s["key"] for s in html_view(mixed_report)["strips"]] == ["attack", "atlas"]


def test_atlas_only_report(ai_report):
    page = parse(render_html(ai_report))
    assert [s["key"] for s in html_view(ai_report)["strips"]] == ["atlas"]
    assert all(c["data-frameworks"] == "atlas" for c in page.find("article", class_="card"))


def test_anchors_are_stable_and_unique(auth_report):
    first = html_view(auth_report)["cards"]
    again = html_view(auth_report)["cards"]
    assert [c["anchor"] for c in first] == [c["anchor"] for c in again]
    assert len({c["anchor"] for c in first}) == len(first)


def test_rule_references_link_only_to_web_addresses(tmp_path):
    rule = tmp_path / "rule.yml"
    rule.write_text(
        "title: Any Cron Session\nid: 5d4f3b8e-27f1-4f53-9b4b-8f4f8ad2c001\nlevel: low\n"
        "references:\n  - javascript:alert(1)\n  - https://example.org/notes\n"
        "logsource: {product: linux, service: auth}\n"
        "detection: {sel: {program: CRON}, condition: sel}\n",
        encoding="utf-8",
    )
    report = build_report(
        analyze(FIXTURES / "authlog" / "auth.log", rules=[rule], year=2024),
        generated_at=GENERATED_AT,
    )
    html = render_html(report)
    hrefs = {a["href"] for a in parse(html).find("a")}
    assert "https://example.org/notes" in hrefs
    assert not any(h.startswith("javascript:") for h in hrefs)
    assert "javascript:alert(1)" in html  # still shown, as text
    assert safe_url("https://example.org/a b") is None


def test_live_report_reloads_without_javascript_too(auth_report):
    from datetime import datetime

    from vigie.timeutils import UTC

    auth_report.watch_started = datetime(2026, 9, 28, 11, 0, tzinfo=UTC)
    auth_report.refresh = 5
    live = render_html(auth_report)
    assert '<noscript><meta http-equiv="refresh" content="5"></noscript>' in live
    assert parse(live).find("body")[0]["data-refresh"] == "5"
    assert parse(live).find("button", id="pause")
    auth_report.refresh = 0
    final = render_html(auth_report)
    assert "http-equiv" not in final
    assert "data-refresh" not in parse(final).find("body")[0]


def test_empty_report_has_no_toolbar(analysis_of):
    report = build_report(analysis_of(), generated_at=GENERATED_AT)
    page = parse(render_html(report))
    assert not page.find(id="toolbar")
    assert page.errors == []
    assert "No alert at level low or above." in render_html(report)


def test_hostile_log_content_stays_text(tmp_path):
    hostile = '</script><script>alert(1)</script>"><img src=x>'
    lines = [
        f"Mar 10 09:00:{i:02d} web01 sshd[1]: Failed password for invalid user {hostile} "
        f"from 203.0.113.9 port {4000 + i} ssh2"
        for i in range(10)
    ]
    (tmp_path / "auth.log").write_text("\n".join(lines) + "\n")
    html = render_html(build_report(analyze(tmp_path, year=2024), generated_at=GENERATED_AT))
    page = parse(html)
    assert page.errors == []
    assert not page.find("img")
    assert all("alert(1)" not in text for _, text in page.scripts)


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_script_parses(auth_report, tmp_path):
    page = parse(render_html(auth_report))
    for n, (attrs, text) in enumerate(page.scripts):
        if attrs.get("type") == "application/json":
            continue
        path = tmp_path / f"script{n}.js"
        path.write_text(text, encoding="utf-8")
        result = subprocess.run(["node", "--check", str(path)], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr


def test_filters():
    assert number(1429) == "1,429"
    from datetime import datetime, timedelta

    start = datetime(2024, 1, 1)
    assert duration(start, start + timedelta(days=3, hours=2)) == "3 days"
    assert duration(start, start + timedelta(days=2200)) == "about 6 years"
    assert duration(start, start + timedelta(minutes=1)) == "1 minute"
    assert duration(start, start + timedelta(seconds=40)) == "40 seconds"
    assert duration(None, start) == ""
    assert re.fullmatch(r"\d+ hours", duration(start, start + timedelta(hours=5)))
