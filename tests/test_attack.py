import importlib.util
import json
from pathlib import Path

import pytest

from vigie.attack import AttackData, default_attack_data

ROOT = Path(__file__).parent.parent


@pytest.fixture(scope="module")
def attack():
    return default_attack_data()


class TestBundledData:
    def test_version_and_copyright(self, attack):
        assert attack.version == "19.2"
        assert attack.copyright.startswith("© 2026 The MITRE Corporation.")

    def test_tactics_in_matrix_order(self, attack):
        names = [tactic.shortname for tactic in attack.tactics]
        assert names[0] == "reconnaissance"
        assert names[-1] == "impact"
        assert names.index("credential-access") < names.index("lateral-movement")

    def test_loaded_once(self):
        assert default_attack_data() is default_attack_data()


class TestLookups:
    def test_sub_technique(self, attack):
        technique = attack.technique("t1003.001")
        assert technique.id == "T1003.001"
        assert technique.display_name == "OS Credential Dumping: LSASS Memory"
        assert technique.tactics == ("credential-access",)
        assert technique.url == "https://attack.mitre.org/techniques/T1003/001"

    def test_technique(self, attack):
        technique = attack.technique("T1110")
        assert technique.display_name == "Brute Force"
        assert technique.parent_name is None

    def test_revoked_id_is_followed(self, attack):
        # "Clear Windows Event Logs" moved to T1685.005 in ATT&CK v19.
        assert attack.technique("T1070.001").id == "T1685.005"

    def test_unknown_technique(self, attack):
        assert attack.technique("T9999") is None

    @pytest.mark.parametrize(
        "name", ["credential-access", "credential_access", "Credential_Access"]
    )
    def test_tactic_spellings(self, attack, name):
        assert attack.tactic(name).id == "TA0006"

    def test_legacy_defense_evasion(self, attack):
        tactic = attack.tactic("defense_evasion")
        assert (tactic.id, tactic.shortname) == ("TA0005", "stealth")

    def test_unknown_tactic(self, attack):
        assert attack.tactic("world-domination") is None


class TestMapTags:
    def test_techniques_define_tactics(self, attack):
        mapping = attack.map_tags(
            ["attack.persistence", "attack.t1053.005", "attack.execution", "attack.s0111"]
        )
        assert [t.id for t in mapping.techniques] == ["T1053.005"]
        # All tactics of the technique, in matrix order, not only the tagged ones.
        assert [t.shortname for t in mapping.tactics] == [
            "execution",
            "persistence",
            "privilege-escalation",
        ]
        assert mapping.unknown == ()

    def test_tactic_tags_are_a_fallback(self, attack):
        mapping = attack.map_tags(["attack.credential_access", "attack.discovery"])
        assert mapping.techniques == ()
        assert [t.shortname for t in mapping.tactics] == ["credential-access", "discovery"]

    def test_non_attack_and_other_attack_tags_are_ignored(self, attack):
        mapping = attack.map_tags(
            ["cve.2021-44228", "detection.threat-hunting", "attack.g0007", "attack.s0002"]
        )
        assert mapping == type(mapping)()

    def test_unknown_tags_are_reported(self, attack):
        mapping = attack.map_tags(["attack.t9999", "attack.world_domination", "attack.t1110"])
        assert mapping.unknown == ("attack.t9999", "attack.world_domination")
        assert [t.id for t in mapping.techniques] == ["T1110"]

    def test_revoked_tags_are_reported_and_resolved(self, attack):
        mapping = attack.map_tags(["attack.defense-evasion", "attack.t1070.001"])
        assert mapping.revoked == (("T1070.001", "T1685.005"),)
        assert [t.id for t in mapping.techniques] == ["T1685.005"]
        assert [t.shortname for t in mapping.tactics] == ["defense-impairment"]

    def test_duplicates_collapse(self, attack):
        mapping = attack.map_tags(["attack.t1110", "attack.T1110", "attack.t1110.001"])
        assert [t.id for t in mapping.techniques] == ["T1110", "T1110.001"]


def load_build_script():
    spec = importlib.util.spec_from_file_location(
        "build_attack_data", ROOT / "tools" / "build_attack_data.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def reference(external_id, path):
    return [
        {
            "source_name": "mitre-attack",
            "external_id": external_id,
            "url": f"https://attack.mitre.org/{path}",
        }
    ]


TINY_BUNDLE = {
    "objects": [
        {
            "type": "x-mitre-collection",
            "id": "collection--1",
            "x_mitre_version": "99.0",
            "modified": "2030-01-01T00:00:00.000Z",
        },
        {"type": "x-mitre-matrix", "id": "matrix--1", "tactic_refs": ["tactic--2", "tactic--1"]},
        {
            "type": "x-mitre-tactic",
            "id": "tactic--1",
            "name": "Impact",
            "x_mitre_shortname": "impact",
            "external_references": reference("TA0040", "tactics/TA0040"),
        },
        {
            "type": "x-mitre-tactic",
            "id": "tactic--2",
            "name": "Execution",
            "x_mitre_shortname": "execution",
            "external_references": reference("TA0002", "tactics/TA0002"),
        },
        {
            "type": "attack-pattern",
            "id": "ap--1",
            "name": "Parent",
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
            "external_references": reference("T0001", "techniques/T0001"),
        },
        {
            "type": "attack-pattern",
            "id": "ap--2",
            "name": "Child",
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "impact"},
                {"kill_chain_name": "other", "phase_name": "ignored"},
            ],
            "external_references": reference("T0001.001", "techniques/T0001/001"),
        },
        {
            "type": "attack-pattern",
            "id": "ap--3",
            "name": "Old",
            "revoked": True,
            "external_references": reference("T0002", "techniques/T0002"),
        },
        {
            "type": "attack-pattern",
            "id": "ap--4",
            "name": "Deprecated",
            "x_mitre_deprecated": True,
            "external_references": reference("T0003", "techniques/T0003"),
        },
        {
            "type": "relationship",
            "id": "relationship--1",
            "relationship_type": "revoked-by",
            "source_ref": "ap--3",
            "target_ref": "ap--2",
        },
        {
            "type": "relationship",
            "id": "relationship--2",
            "relationship_type": "revoked-by",
            "source_ref": "ap--4",
            "target_ref": "ap--3",
        },
    ]
}


def test_build_script_extracts_what_vigie_needs(tmp_path):
    script = load_build_script()
    bundle = tmp_path / "bundle.json"
    bundle.write_text(json.dumps(TINY_BUNDLE))
    output = tmp_path / "out" / "attack.json"
    assert script.main(["--input", str(bundle), "--output", str(output)]) == 0

    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["attack_version"] == "99.0"
    assert data["copyright"].startswith("© 2030 The MITRE Corporation.")
    assert [t["shortname"] for t in data["tactics"]] == ["execution", "impact"]
    assert data["techniques"] == {
        "T0001": {
            "name": "Parent",
            "tactics": ["execution"],
            "url": "https://attack.mitre.org/techniques/T0001",
        },
        "T0001.001": {
            "name": "Child",
            "tactics": ["impact"],
            "url": "https://attack.mitre.org/techniques/T0001/001",
        },
    }
    # Revoked to an active technique: kept. Revoked to another revoked one: dropped.
    assert data["revoked"] == {"T0002": "T0001.001"}

    attack = AttackData.load(output)
    assert attack.technique("T0002").display_name == "Parent: Child"
