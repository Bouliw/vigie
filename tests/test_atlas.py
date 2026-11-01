import importlib.util
import json
from pathlib import Path

import pytest
import yaml

from vigie.atlas import AtlasData, default_atlas_data

ROOT = Path(__file__).parent.parent


@pytest.fixture(scope="module")
def atlas():
    return default_atlas_data()


class TestBundledData:
    def test_version_and_copyright(self, atlas):
        assert atlas.version == "2026.10"
        assert atlas.copyright == (
            "MITRE ATLAS data: Copyright 2021-2026 MITRE, "
            "licensed under the Apache License, Version 2.0."
        )

    def test_tactics_in_matrix_order(self, atlas):
        names = [tactic.shortname for tactic in atlas.tactics]
        assert len(names) == 16
        assert names[:5] == [
            "reconnaissance",
            "resource-development",
            "ai-attack-adaptation",
            "initial-access",
            "ai-model-access",
        ]
        assert names[-1] == "impact"
        assert names.index("execution") < names.index("exfiltration")

    def test_summaries(self, atlas):
        assert atlas.summary("AML.TA0005") == (
            "The adversary is trying to run malicious code embedded in AI artifacts or software."
        )
        assert atlas.summary("AML.T0051.001").startswith("An adversary may inject prompts")
        assert all(atlas.summary(t.id) for t in atlas.tactics)

    def test_loaded_once(self):
        assert default_atlas_data() is default_atlas_data()


class TestLookups:
    def test_sub_technique(self, atlas):
        technique = atlas.technique("aml.t0051.001")
        assert technique.id == "AML.T0051.001"
        assert technique.display_name == "LLM Prompt Injection: Indirect"
        assert technique.tactics == ("execution",)
        assert technique.url == "https://atlas.mitre.org/techniques/AML.T0051.001"

    def test_technique(self, atlas):
        technique = atlas.technique("AML.T0054")
        assert technique.display_name == "LLM Jailbreak"
        assert technique.parent_name is None
        assert technique.tactics == ("defense-evasion", "privilege-escalation")

    def test_unknown_technique(self, atlas):
        assert atlas.technique("AML.T9999") is None

    def test_techniques_moved_in_2026_10(self, atlas):
        # ATLAS 2026.10 moved "Extract LLM System Prompt" and "LLM Data Leakage" under
        # Data from AI Services: rules must use the new ids.
        assert atlas.technique("AML.T0056") is None
        assert atlas.technique("AML.T0057") is None
        assert atlas.technique("AML.T0085.003").display_name == (
            "Data from AI Services: System Instructions"
        )
        assert atlas.technique("AML.T0085.002").tactics == ("collection",)

    @pytest.mark.parametrize("name", ["ai-model-access", "ai_model_access", "AML.TA0000"])
    def test_tactic_spellings(self, atlas, name):
        tactic = atlas.tactic(name)
        assert (tactic.id, tactic.name) == ("AML.TA0000", "AI Model Access")
        assert tactic.url == "https://atlas.mitre.org/tactics/AML.TA0000"

    def test_unknown_tactic(self, atlas):
        assert atlas.tactic("world-domination") is None
        assert atlas.tactic("aml.ta9999") is None


class TestMapTags:
    def test_techniques_define_tactics(self, atlas):
        mapping = atlas.map_tags(["atlas.privilege-escalation", "atlas.aml.t0053", "attack.t1059"])
        assert [t.id for t in mapping.techniques] == ["AML.T0053"]
        # All tactics of the technique, in matrix order, not only the tagged ones.
        assert [t.shortname for t in mapping.tactics] == [
            "execution",
            "privilege-escalation",
            "lateral-movement",
        ]
        assert mapping.unknown == ()

    def test_tactic_tags_are_a_fallback(self, atlas):
        mapping = atlas.map_tags(["atlas.exfiltration", "atlas.aml.ta0000"])
        assert mapping.techniques == ()
        assert [t.shortname for t in mapping.tactics] == ["ai-model-access", "exfiltration"]

    def test_attack_and_other_atlas_tags_are_ignored(self, atlas):
        mapping = atlas.map_tags(["attack.t1110", "attack.execution", "atlas.aml.m0015"])
        assert mapping == type(mapping)()

    def test_unknown_tags_are_reported(self, atlas):
        mapping = atlas.map_tags(["atlas.aml.t9999", "atlas.world-domination", "atlas.aml.t0086"])
        assert mapping.unknown == ("atlas.aml.t9999", "atlas.world-domination")
        assert [t.id for t in mapping.techniques] == ["AML.T0086"]

    def test_duplicates_collapse(self, atlas):
        mapping = atlas.map_tags(["atlas.aml.t0051", "atlas.AML.T0051", "atlas.aml.t0051.000"])
        assert [t.id for t in mapping.techniques] == ["AML.T0051", "AML.T0051.000"]


def load_build_script():
    spec = importlib.util.spec_from_file_location(
        "build_atlas_data", ROOT / "tools" / "build_atlas_data.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TINY_ATLAS = {
    "format-version": "6.0.0",
    "collection": {"id": "ATLAS-collection", "version": "2099.01", "modified-date": "2099-01-31"},
    "matrix": {"id": "ATLAS-matrix", "name": "ATLAS"},
    "tactics": {
        "AML.TA0005": {"id": "AML.TA0005", "name": "Execution"},
        "AML.TA0000": {"id": "AML.TA0000", "name": "AI Model Access"},
    },
    "techniques": {
        "AML.T0001": {"id": "AML.T0001", "name": "Parent"},
        "AML.T0001.000": {"id": "AML.T0001.000", "name": "Child"},
    },
    "relationships": {
        "ATLAS-matrix": {
            "sequences": [
                {"target": "AML.TA0005", "position": 2},
                {"target": "AML.TA0000", "position": 1},
            ]
        },
        "AML.T0001": {"achieves": [{"target": "AML.TA0000"}, {"target": "AML.TA0005"}]},
        "AML.T0001.000": {
            "achieves": [{"target": "AML.TA0005"}],
            "specializes": [{"target": "AML.T0001"}],
        },
    },
}


def test_build_script_extracts_what_vigie_needs(tmp_path):
    script = load_build_script()
    source = tmp_path / "ATLAS.yaml"
    source.write_text(yaml.safe_dump(TINY_ATLAS))
    output = tmp_path / "out" / "atlas.json"
    assert script.main(["--input", str(source), "--output", str(output)]) == 0

    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["atlas_version"] == "2099.01"
    assert data["copyright"].startswith("MITRE ATLAS data: Copyright 2021-2099 MITRE")
    assert [t["shortname"] for t in data["tactics"]] == ["ai-model-access", "execution"]
    assert data["tactics"][0]["url"] == "https://atlas.mitre.org/tactics/AML.TA0000"
    assert data["techniques"] == {
        "AML.T0001": {
            "name": "Parent",
            "tactics": ["ai-model-access", "execution"],
            "url": "https://atlas.mitre.org/techniques/AML.T0001",
        },
        "AML.T0001.000": {
            "name": "Child",
            "tactics": ["execution"],
            "url": "https://atlas.mitre.org/techniques/AML.T0001.000",
        },
    }

    atlas = AtlasData.load(output)
    assert atlas.technique("AML.T0001.000").display_name == "Parent: Child"
    assert atlas.summary("AML.T0001") == ""


def test_build_script_keeps_a_plain_text_summary(tmp_path):
    script = load_build_script()
    data = json.loads(json.dumps(TINY_ATLAS))
    data["techniques"]["AML.T0001"]["description"] = (
        "An adversary may hide text (See [Obfuscation](/techniques/AML.T0068)) in a page.\n\n"
        "More detail."
    )
    data["tactics"]["AML.TA0005"]["description"] = "The adversary is trying to run code."
    source = tmp_path / "ATLAS.yaml"
    source.write_text(yaml.safe_dump(data))
    output = tmp_path / "atlas.json"
    assert script.main(["--input", str(source), "--output", str(output)]) == 0
    atlas = AtlasData.load(output)
    assert atlas.summary("AML.T0001") == "An adversary may hide text (See Obfuscation) in a page."
    assert atlas.summary("aml.ta0005") == "The adversary is trying to run code."
    assert atlas.summary("AML.T0001.000") == ""


def test_build_script_rejects_the_old_format(tmp_path):
    script = load_build_script()
    source = tmp_path / "ATLAS.yaml"
    source.write_text(yaml.safe_dump({"id": "ATLAS", "version": "5.6.0", "matrices": []}))
    with pytest.raises(SystemExit, match="expected ATLAS data format 6"):
        script.main(["--input", str(source), "--output", str(tmp_path / "atlas.json")])


MANIFEST = """
- release: '2026.09'
  versions:
  - {format-version: 6.0.0, path: v6/ATLAS-2026.09.yaml}
- release: '2026.04'
  versions:
  - {format-version: 6.0.0, path: v6/ATLAS-2026.04.yaml}
  - {format-version: 5.6.0, path: legacy/ATLAS-5.6.0.yaml}
"""


def test_build_script_finds_releases_in_the_manifest():
    script = load_build_script()
    assert script.release_path(MANIFEST, None) == "v6/ATLAS-2026.09.yaml"
    assert script.release_path(MANIFEST, "2026.04") == "v6/ATLAS-2026.04.yaml"
    with pytest.raises(SystemExit, match="not found"):
        script.release_path(MANIFEST, "1999.01")
