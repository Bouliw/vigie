import pytest
import yaml

from vigie.owasp import OwaspMapping, default_owasp_data
from vigie.rules import RULES_DIR


@pytest.fixture(scope="module")
def owasp():
    return default_owasp_data()


class TestLists:
    def test_llm_top_10_2025(self, owasp):
        llm = owasp.lists[0]
        assert (llm.key, llm.title, llm.edition) == (
            "llm",
            "OWASP Top 10 for LLM Applications 2025",
            "2025",
        )
        assert llm.url == "https://genai.owasp.org/llm-top-10/"
        assert [item.display_name for item in llm.items] == [
            "LLM01:2025 Prompt Injection",
            "LLM02:2025 Sensitive Information Disclosure",
            "LLM03:2025 Supply Chain",
            "LLM04:2025 Data and Model Poisoning",
            "LLM05:2025 Improper Output Handling",
            "LLM06:2025 Excessive Agency",
            "LLM07:2025 System Prompt Leakage",
            "LLM08:2025 Vector and Embedding Weaknesses",
            "LLM09:2025 Misinformation",
            "LLM10:2025 Unbounded Consumption",
        ]
        # Each entry has its own page; the first one kept its 2023 address.
        assert llm.items[0].url == "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"
        assert llm.items[9].url == (
            "https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/"
        )
        assert all(
            item.url
            == f"https://genai.owasp.org/llmrisk/{item.id[:5].lower()}2025-"
            + item.name.lower().replace(" ", "-")
            + "/"
            for item in llm.items[1:]
        )

    def test_agentic_top_10_2026(self, owasp):
        agentic = owasp.lists[1]
        assert (agentic.key, agentic.title, agentic.edition) == (
            "asi",
            "OWASP Top 10 for Agentic Applications 2026",
            "2026",
        )
        assert [item.display_name for item in agentic.items] == [
            "ASI01 Agent Goal Hijack",
            "ASI02 Tool Misuse and Exploitation",
            "ASI03 Identity and Privilege Abuse",
            "ASI04 Agentic Supply Chain Vulnerabilities",
            "ASI05 Unexpected Code Execution",
            "ASI06 Memory and Context Poisoning",
            "ASI07 Insecure Inter-Agent Communication",
            "ASI08 Cascading Failures",
            "ASI09 Human-Agent Trust Exploitation",
            "ASI10 Rogue Agents",
        ]
        # The list has no page per entry: every entry links to the document.
        assert {item.url for item in agentic.items} == {
            "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"
        }

    def test_attribution(self, owasp):
        assert "OWASP GenAI Security Project" in owasp.copyright
        assert "CC BY-SA 4.0" in owasp.copyright

    def test_built_once(self):
        assert default_owasp_data() is default_owasp_data()


class TestLookups:
    @pytest.mark.parametrize("spelling", ["LLM01:2025", "llm01:2025", "llm01", "LLM01"])
    def test_llm_spellings(self, owasp, spelling):
        assert owasp.item(spelling).id == "LLM01:2025"

    @pytest.mark.parametrize("spelling", ["ASI04", "asi04", "ASI04:2026"])
    def test_agentic_spellings(self, owasp, spelling):
        item = owasp.item(spelling)
        assert (item.id, item.name) == ("ASI04", "Agentic Supply Chain Vulnerabilities")

    @pytest.mark.parametrize(
        "unknown", ["LLM01:2023", "LLM11", "ASI00", "ASI04:2025", "A01:2021", "llm1", ""]
    )
    def test_unknown_entries(self, owasp, unknown):
        assert owasp.item(unknown) is None


class TestMapTags:
    def test_entries_in_list_order(self, owasp):
        mapping = owasp.map_tags(["owasp.asi04", "atlas.aml.t0110", "owasp.llm01", "attack.t1110"])
        assert [item.id for item in mapping.items] == ["LLM01:2025", "ASI04"]
        assert mapping.unknown == ()

    def test_duplicates_collapse(self, owasp):
        mapping = owasp.map_tags(["owasp.llm02", "OWASP.LLM02", "owasp.llm02"])
        assert [item.id for item in mapping.items] == ["LLM02:2025"]

    def test_unknown_tags_are_reported(self, owasp):
        mapping = owasp.map_tags(["owasp.llm11", "owasp.top10", "owasp.asi01"])
        assert mapping.unknown == ("owasp.llm11", "owasp.top10")
        assert [item.id for item in mapping.items] == ["ASI01"]

    def test_other_tags_are_ignored(self, owasp):
        assert owasp.map_tags(["atlas.execution", "attack.t1059", "cve.2024-1"]) == OwaspMapping()


# The OWASP entries of each AI rule. Like the correlation parameters in
# tests/rules/test_rules.py, they are pinned here: changing one must be a
# deliberate decision, made in the rule and in this table.
MAPPING = {
    "ai_excessive_prompts.yml": ["LLM10:2025"],
    "ai_hidden_unicode_tag_text.yml": ["LLM01:2025", "ASI01"],
    "ai_jailbreak_attempt.yml": ["LLM01:2025", "ASI01"],
    "ai_mcp_tool_poisoning.yml": ["LLM01:2025", "ASI04"],
    "ai_personal_data_in_response.yml": ["LLM02:2025"],
    "ai_prompt_injection_direct.yml": ["LLM01:2025", "ASI01"],
    "ai_prompt_injection_indirect.yml": ["LLM01:2025", "ASI01"],
    "ai_response_image_exfiltration.yml": ["LLM02:2025", "LLM05:2025"],
    "ai_secret_in_response.yml": ["LLM02:2025"],
    "ai_sensitive_tool_call.yml": ["LLM06:2025", "ASI02"],
    "ai_system_prompt_extraction_attempt.yml": ["LLM07:2025"],
    "ai_system_prompt_leak.yml": ["LLM02:2025", "LLM07:2025"],
    "ai_tool_call_after_prompt_injection.yml": ["LLM01:2025", "LLM06:2025", "ASI01", "ASI02"],
    "ai_tool_call_credential_access.yml": ["ASI03"],
    "ai_tool_call_download_and_run.yml": ["ASI02", "ASI05"],
    "ai_tool_call_exfiltration_url.yml": ["LLM02:2025", "ASI02"],
    "ai_user_prompt.yml": ["LLM10:2025"],
}


def test_every_ai_rule_has_its_pinned_mapping(owasp):
    paths = sorted((RULES_DIR / "ai").glob("*.yml"))
    assert [path.name for path in paths] == sorted(MAPPING)
    for path in paths:
        tags = yaml.safe_load(path.read_text(encoding="utf-8"))["tags"]
        assert [item.id for item in owasp.map_tags(tags).items] == MAPPING[path.name], path.name
