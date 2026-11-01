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
from vigie.rules import RULES_DIR

from .conftest import FIXTURES, GENERATED_AT

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


def external_links(parser):
    """Links that leave the page (in-page anchors excluded)."""
    return [attrs["href"] for tag, attrs in parser.tags if tag == "a" and attrs["href"][0] != "#"]


def rule_references(report):
    return {ref for alert in report.alerts for ref in alert.rule.references}


def test_html_is_self_contained(auth_report):
    html = render_html(auth_report)
    parser = Tags()
    parser.feed(html)
    names = [tag for tag, _ in parser.tags]
    assert names[0] == "html"
    # Styles and scripts are inline: nothing is loaded from elsewhere, so it works offline.
    assert "link" not in names
    assert "img" not in names
    assert "iframe" not in names
    assert all("src" not in attrs for tag, attrs in parser.tags if tag == "script")
    assert not any(tag == "use" and not attrs["href"].startswith("#") for tag, attrs in parser.tags)
    cards = [attrs for tag, attrs in parser.tags if tag == "article" and "card" in attrs["class"]]
    assert len(cards) == auth_report.alert_count
    # Links leave the file only for ATT&CK pages and the references the rules give.
    hrefs = external_links(parser)
    assert hrefs and all(
        h.startswith("https://attack.mitre.org/") or h in rule_references(auth_report)
        for h in hrefs
    )


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


@pytest.fixture
def atlas_report(atlas_rule):
    analysis = analyze(FIXTURES / "authlog" / "auth.log", rules=[atlas_rule], year=2024)
    return build_report(analysis, generated_at=GENERATED_AT)


def test_markdown_shows_atlas_like_attack(atlas_report):
    text = render_markdown(atlas_report)
    assert "Alerts are mapped to MITRE ATT&CK 19.2 and MITRE ATLAS 2026.10." in text
    assert "## MITRE ATT&CK" not in text  # no ATT&CK technique among the alerts
    assert "## MITRE ATLAS" in text
    assert (
        "| [Execution](https://atlas.mitre.org/tactics/AML.TA0005) (AML.TA0005) | 3 | "
        "[AML.T0051.000](https://atlas.mitre.org/techniques/AML.T0051.000) "
        "LLM Prompt Injection: Direct<br>"
        "[AML.T0053](https://atlas.mitre.org/techniques/AML.T0053) AI Agent Tool Invocation |"
    ) in text
    assert (
        "- **ATLAS:** [AML.T0051.000](https://atlas.mitre.org/techniques/AML.T0051.000) "
        "LLM Prompt Injection: Direct; [AML.T0053](https://atlas.mitre.org/techniques/AML.T0053) "
        "AI Agent Tool Invocation (Execution, Privilege Escalation, Lateral Movement)\n"
        "- **Rule:**"
    ) in text
    assert "**ATT&CK:**" not in text
    assert "MITRE ATLAS data: Copyright 2021-2026 MITRE" in text


def test_html_shows_atlas_like_attack(atlas_report):
    html = render_html(atlas_report)
    assert "<h2>MITRE ATLAS</h2>" in html
    assert "<h2>MITRE ATT&amp;CK</h2>" not in html
    assert "<dt>ATLAS</dt>" in html
    assert "<dt>ATT&amp;CK</dt>" not in html
    assert "MITRE ATLAS data: Copyright 2021-2026 MITRE" in html
    parser = Tags()
    parser.feed(html)
    hrefs = external_links(parser)
    assert "https://atlas.mitre.org/techniques/AML.T0053" in hrefs
    assert all(
        h.startswith(("https://attack.mitre.org/", "https://atlas.mitre.org/")) for h in hrefs
    )


def test_json_has_the_atlas_mapping(atlas_report):
    data = json.loads(render_json(atlas_report))
    assert data["atlas_version"] == "2026.10"
    assert data["atlas_tactics"][0]["tactic"]["id"] == "AML.TA0005"
    assert data["alerts"][0]["atlas"]["techniques"][0]["id"] == "AML.T0051.000"


def test_reports_without_atlas_alerts_do_not_mention_it(auth_report):
    for text in (render_markdown(auth_report), render_html(auth_report)):
        assert "ATLAS" not in text


def test_mixed_report_shows_both_frameworks(atlas_rule):
    analysis = analyze(
        FIXTURES / "authlog" / "auth.log", rules=[atlas_rule, RULES_DIR / "linux"], year=2024
    )
    text = render_markdown(build_report(analysis, generated_at=GENERATED_AT))
    assert text.index("## MITRE ATT&CK") < text.index("## MITRE ATLAS") < text.index("## Alerts")
    brute_force = text[text.index("SSH Brute Force (medium)") :]
    brute_force = brute_force[: brute_force.index("**Rule:**")]
    assert "**ATT&CK:**" in brute_force
    assert "**ATLAS:**" not in brute_force


def test_ai_agent_report_links_atlas(analysis_of):
    analysis = analysis_of(
        "agentlog/agent_indirect_injection.jsonl", "agentlog/agent_data_leak.jsonl"
    )
    report = build_report(analysis, generated_at=GENERATED_AT)
    text = render_markdown(report)
    assert "## MITRE ATLAS" in text and "## MITRE ATT&CK" not in text
    assert (
        "[AML.T0051.001](https://atlas.mitre.org/techniques/AML.T0051.001) "
        "LLM Prompt Injection: Indirect"
    ) in text
    assert "[Exfiltration](https://atlas.mitre.org/tactics/AML.TA0010) (AML.TA0010)" in text
    html = render_html(report)
    parser = Tags()
    parser.feed(html)
    hrefs = set(external_links(parser))
    assert "https://atlas.mitre.org/techniques/AML.T0077" in hrefs
    assert "https://genai.owasp.org/llmrisk/llm01-prompt-injection/" in hrefs
    assert all(
        h.startswith(("https://atlas.mitre.org/", "https://genai.owasp.org/"))
        or h in rule_references(report)
        for h in hrefs
    )
    # Log content is escaped: the markdown image of the response stays text.
    assert "img" not in [tag for tag, _ in parser.tags]
    assert "!\\[logo\\](https://img.evil.example/c.png" in text  # escaped, never rendered


@pytest.fixture
def owasp_report(analysis_of):
    analysis = analysis_of(
        "agentlog/agent_indirect_injection.jsonl", "agentlog/agent_mcp_poisoned_tool.jsonl"
    )
    return build_report(analysis, generated_at=GENERATED_AT)


def test_markdown_shows_owasp_next_to_atlas(owasp_report):
    text = render_markdown(owasp_report)
    assert (
        "Alerts are mapped to MITRE ATT&CK 19.2 and MITRE ATLAS 2026.10, and to the OWASP Top 10 "
        "for LLM Applications 2025 and the OWASP Top 10 for Agentic Applications 2026."
    ) in text
    assert text.index("## MITRE ATLAS") < text.index("## OWASP Top 10") < text.index("## Alerts")
    section = text[text.index("## OWASP Top 10") : text.index("## Alerts")]
    assert section.index("### OWASP Top 10 for LLM Applications 2025") < section.index(
        "### OWASP Top 10 for Agentic Applications 2026"
    )
    assert (
        "| [LLM01:2025](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) Prompt Injection "
        "| 5 | Poisoned MCP Tool Description<br>"
        "AI Agent Sensitive Tool Call After Prompt Injection<br>"
        "Invisible Unicode Tag Text In LLM Input<br>"
        "LLM Prompt Injection In Retrieved Content Or Tool Result |"
    ) in section
    assert (
        "| [ASI04](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)"
        " Agentic Supply Chain Vulnerabilities | 2 | Poisoned MCP Tool Description |"
    ) in section
    poisoned = text[text.index("Poisoned MCP Tool Description (high)") :]
    poisoned = poisoned[: poisoned.index("- **Author:**")]
    assert (
        "- **ATLAS:** [AML.T0110](https://atlas.mitre.org/techniques/AML.T0110) "
        "AI Agent Tool Poisoning (Persistence)\n"
        "- **OWASP:** [LLM01:2025](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) "
        "Prompt Injection; [ASI04](https://genai.owasp.org/resource/"
        "owasp-top-10-for-agentic-applications-for-2026/) Agentic Supply Chain Vulnerabilities\n"
        "- **Rule:**"
    ) in poisoned
    assert "OWASP GenAI Security Project, licensed under CC BY-SA 4.0." in text


def test_html_shows_owasp_next_to_atlas(owasp_report):
    html = render_html(owasp_report)
    assert "<h2>OWASP Top 10</h2>" in html
    assert html.index("<h2>MITRE ATLAS</h2>") < html.index("<h2>OWASP Top 10</h2>")
    assert html.index("OWASP Top 10 for LLM Applications 2025</a></h3>") < html.index(
        "OWASP Top 10 for Agentic Applications 2026</a></h3>"
    )
    assert "<dt>OWASP</dt>" in html
    assert "and to the OWASP Top 10 for LLM Applications 2025" in html
    assert "OWASP GenAI Security Project, licensed under CC BY-SA 4.0." in html
    parser = Tags()
    parser.feed(html)
    hrefs = set(external_links(parser))
    assert {
        "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
        "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
        "https://genai.owasp.org/llm-top-10/",
    } <= hrefs
    # Each rule of the OWASP tables filters the alerts, like the rules that fired.
    rules = {
        attrs["data-rule"]
        for tag, attrs in parser.tags
        if tag == "button" and attrs.get("class") == "rule-link"
    }
    assert rules == {alert.rule.id for alert in owasp_report.alerts}


def test_json_has_the_owasp_mapping(owasp_report):
    data = json.loads(render_json(owasp_report))
    assert [group["list"]["key"] for group in data["owasp"]] == ["llm", "asi"]
    first = data["owasp"][0]["items"][0]
    assert first["item"]["id"] == "LLM01:2025" and first["alert_count"] == 5
    (poisoned, *_) = [a for a in data["alerts"] if a["rule"]["title"].startswith("Poisoned")]
    assert [item["id"] for item in poisoned["owasp"]["items"]] == ["LLM01:2025", "ASI04"]


def test_reports_without_ai_alerts_do_not_mention_owasp(auth_report, atlas_report):
    for report in (auth_report, atlas_report):
        for text in (render_markdown(report), render_html(report)):
            assert "OWASP" not in text
