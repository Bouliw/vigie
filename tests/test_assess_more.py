"""Threat profiles, detection coverage, comparison and mapping from the wording."""

import json
import random
import shutil
import subprocess

import pytest

from vigie.assess import questionnaire as q
from vigie.assess.engine import assess, detection_of
from vigie.assess.knowledge import ProfileError, default_knowledge
from vigie.assess.render import render_html, render_json, render_markdown, to_dict
from vigie.assess.suggest import map_questionnaire, normalize, suggest
from vigie.atlas import default_atlas_data
from vigie.attack import default_attack_data
from vigie.cli import main
from vigie.rules import RULES_DIR
from vigie.sigma.loader import load_rules

NODE = shutil.which("node")
KNOWLEDGE = default_knowledge()


def answered(seed: int) -> q.Questionnaire:
    rng = random.Random(seed)
    generic = q.generic()
    return generic.with_answers(
        {c.id: rng.choice([None, 0, 1, 2, 3, 4, 5]) for c in generic.controls}
    )


# --- Threat profiles --------------------------------------------------------------------


def test_groups_carry_their_techniques_and_sectors():
    groups = {group.name: group for group in KNOWLEDGE.groups}
    assert len(groups) > 150
    apt29 = groups["APT29"]
    assert apt29.id == "G0016" and "T1078" in apt29.techniques
    assert all("." not in t for t in apt29.techniques)
    assert "government" in apt29.sectors
    assert KNOWLEDGE.sectors["healthcare"] == "Healthcare and life sciences"


def test_a_sector_profile_keeps_the_techniques_of_its_groups():
    profile = KNOWLEDGE.profile("healthcare")
    assert profile.sector == "healthcare" and len(profile.groups) >= 10
    assert profile.label == "groups that target Healthcare and life sciences"
    assert KNOWLEDGE.profile("Healthcare").groups == profile.groups
    result = assess(answered(1), profile=profile)
    attack = result.framework("attack")
    ids = {t.technique.id for s in attack.stages for t in s.techniques}
    assert ids and ids <= profile.techniques
    # ATLAS has no groups: the profile leaves it whole.
    whole = assess(answered(1))
    assert result.framework("atlas").counts == whole.framework("atlas").counts
    assert sum(attack.counts.values()) < sum(whole.framework("attack").counts.values())


def test_groups_are_named_by_id_name_or_alias():
    profile = KNOWLEDGE.profile(groups=["g0016", "Cozy Bear", "FIN7"])
    assert profile.groups == ("G0016", "G0046")
    assert profile.label == "APT29, FIN7" and profile.sector == ""
    with pytest.raises(ProfileError, match="unknown ATT&CK group: Nobody"):
        KNOWLEDGE.profile(groups=["Nobody"])
    with pytest.raises(ProfileError, match="unknown sector"):
        KNOWLEDGE.profile("bakeries")


# --- Detection --------------------------------------------------------------------------


def test_detection_counts_rules_per_parent_technique():
    ruleset = load_rules(RULES_DIR)
    rules = [*ruleset.detections, *ruleset.correlations]
    detection = detection_of(rules, (default_attack_data(), default_atlas_data()))
    assert detection["T1110"] >= 1 and all("." not in k or k.startswith("AML.") for k in detection)
    assert all(k.count(".") <= 1 for k in detection)
    result = assess(answered(2), detection=detection, detection_source="the shipped rules")
    spots = result.blind_spots
    assert spots and all(t.status in ("facilitated", "unpreventable") for t in spots)
    assert all(not t.detected for t in spots)
    detected = [t for s in result.framework("attack").stages for t in s.techniques if t.detected]
    assert detected
    markdown = render_markdown(result)
    assert "## Neither prevented nor detected" in markdown and "the shipped rules" in markdown
    assert to_dict(result)["detection"]["blind_spots"] == [t.technique.id for t in spots]


def test_no_detection_means_no_blind_spot_claimed():
    result = assess(answered(2))
    assert result.blind_spots == [] and to_dict(result)["detection"] is None
    assert "Neither prevented" not in render_markdown(result)


# --- Comparison -------------------------------------------------------------------------


def test_comparison_with_a_baseline():
    before = q.generic().with_answers({c.id: 1 for c in q.generic().controls})
    after = before.with_answers({c.id: 4 for c in before.controls[:20]})
    result = assess(after, baseline=before)
    changes = result.comparison()
    attack = next(change for change in changes if change.key == "attack")
    assert attack.index_after < attack.index_before and attack.index_change < 0
    assert attack.improved and not attack.worsened
    assert len(result.changed_controls()) == 20
    text = render_markdown(result)
    assert "## Since" in text and "| Control | Before | Now |" in text
    data = to_dict(result)["comparison"]
    assert data["frameworks"][0]["exposure_index"] == [attack.index_before, attack.index_after]
    assert len(data["controls"]) == 20
    assert assess(after).comparison() == []


# --- Mapping from the wording -----------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "first"),
    [
        ("Authentification forte (MFA) pour les accès distants", "M1032"),
        ("Les comptes administrateurs passent par un bastion", "M1026"),
        ("Sauvegardes hors ligne testées", "M1053"),
        ("Gestion des correctifs de sécurité", "M1051"),
        ("Patch management for servers", "M1051"),
        ("Garde-fous sur les prompts du chatbot", "AML.M0020"),
        ("Validation humaine des actions des agents IA", "AML.M0029"),
    ],
)
def test_suggest_reads_english_and_french(text, first):
    assert suggest(text)[0].mitigation == first


def test_suggest_needs_ai_words_for_ai_mitigations():
    plain = {s.mitigation for s in suggest("Chiffrement des disques des serveurs")}
    assert "M1041" in plain and "AML.M0012" not in plain
    ai = {s.mitigation for s in suggest("Chiffrement des données d'entraînement de l'IA")}
    assert {"M1041", "AML.M0012"} <= ai
    assert suggest("Comité de pilotage trimestriel") == []
    assert normalize("Réseaux élevés") == "reseau eleve"


def test_map_questionnaire_fills_only_unmapped_controls(tmp_path):
    path = tmp_path / "controls.csv"
    path.write_text(
        "Réf.;Point de contrôle;Mesures MITRE;Niveau\n"
        "C1;Authentification forte (MFA);;2\n"
        "C2;Bastion pour les comptes administrateurs;M1018;1\n"
        "C3;Comité de pilotage;;3\n",
        encoding="utf-8",
    )
    questionnaire = q.load(path)
    assert any("control C1 maps to no" in w for w in questionnaire.warnings)
    mapped, report = map_questionnaire(questionnaire)
    by_id = {c.id: c for c in mapped.controls}
    assert by_id["C1"].mitigations[0] == "M1032"
    assert by_id["C2"].mitigations == ("M1018",)  # named ids are kept as they are
    assert by_id["C3"].mitigations == ()
    assert not any("control C1 maps to no" in w for w in mapped.warnings)
    assert any("control C3 maps to no" in w for w in mapped.warnings)
    assert [bool(item.suggestions) for item in report] == [True, False, False]


def test_cli_maps_profiles_compares_and_checks_detection(tmp_path, capsys):
    current = tmp_path / "now.csv"
    current.write_text(
        "Réf.;Domaine;Point de contrôle;Niveau de maturité\n"
        "C1;Identités;Authentification forte (MFA) pour les accès distants;3\n"
        "C2;Identités;Comptes administrateurs via un bastion;2\n"
        "C3;Continuité;Sauvegardes hors ligne testées;1\n",
        encoding="utf-8",
    )
    before = tmp_path / "before.csv"
    before.write_text(current.read_text(encoding="utf-8").replace(";3\n", ";1\n"), "utf-8")
    out = tmp_path / "out"
    args = ["assess", str(current), "-o", str(out), "--no-open", "--plain"]
    assert main(args) == 2
    assert "add --map" in capsys.readouterr().err
    args += ["--map", "--sector", "financial", "--group", "APT29", "--baseline", str(before)]
    assert main([*args, "--format", "html,md,json"]) == 0
    stdout = capsys.readouterr().out
    assert "Mapped 3 control(s) from their wording" in stdout
    assert "Threat profile: APT29" in stdout or "Threat profile:" in stdout
    assert "Since the baseline, MITRE ATT&CK" in stdout
    assert "do not detect" in stdout
    mapped = (out / "questionnaire-mapped.csv").read_text(encoding="utf-8-sig")
    assert "mapped by vigie" in mapped.splitlines()[0] and "M1032 likely" in mapped
    data = json.loads((out / "assessment.json").read_text(encoding="utf-8"))
    assert data["profile"]["groups"] and data["comparison"]["controls"]
    assert data["detection"]["source"].startswith("the ")
    page = (out / "assessment.html").read_text(encoding="utf-8")
    assert '"suggested"' in page and '"baseline"' in page


def test_cli_rejects_an_unknown_sector(tmp_path, capsys):
    args = ["assess", "--sector", "bakeries", "-o", str(tmp_path / "o"), "--no-open"]
    assert main(args) == 2
    assert "unknown sector" in capsys.readouterr().err


# --- The page agrees with Python --------------------------------------------------------

HARNESS = """
const fs = require("fs");
const html = fs.readFileSync(process.argv[2], "utf8");
const texts = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));
const data = html.split('id="vigie-data">')[1].split("</script>")[0];
const script = html.split(/<script>\\r?\\n/).pop().split("</script>")[0];
const OPEN = ["facilitated", "unpreventable"];
const window = { __vigieAssessTest: function (api) {
  const r = api.compute(api.DATA.controls);
  const out = {
    frameworks: r.frameworks.map(f => ({
      key: f.fw.key, index: f.index, counts: f.counts, blocked: f.blockedAt,
      path: f.path.map(s => s.step ? s.step.t.id : null),
      blind: f.evaluated.filter(e => OPEN.includes(e.status) && !e.detected).map(e => e.t.id)
    })),
    priorities: r.priorities.map(p => [p.control.id, p.relieved]),
    suggestions: texts.map(t => api.suggest(t).map(s => [s.mitigation, s.score, s.terms]))
  };
  if (api.DATA.baseline) {
    const base = api.compute(api.DATA.baseline.controls);
    out.compare = r.frameworks.map((f, i) => {
      const c = api.compareFw(base.frameworks[i], f);
      return { key: c.key, index: [c.before, c.after], improved: c.improved, worsened: c.worsened };
    });
  }
  process.stdout.write(JSON.stringify(out));
} };
const document = { getElementById: () => ({ textContent: data }) };
new Function("window", "document", script)(window, document);
"""

TEXTS = [
    "Authentification forte (MFA) pour les accès distants VPN",
    "Les comptes administrateurs passent par un bastion",
    "Garde-fous sur les prompts du chatbot IA (injection de prompt)",
    "Chiffrement des données d'entraînement du modèle IA",
    "Firewall rules and network segmentation between zones",
    "Comité de pilotage",
    "Sauvegardes hors ligne testées, restauration annuelle",
]


@pytest.mark.skipif(NODE is None, reason="needs Node.js")
@pytest.mark.parametrize(
    ("seed", "sector", "groups"),
    [(1, "healthcare", ()), (2, "", ("APT29", "FIN7")), (3, "", ())],
)
def test_the_page_and_python_agree_on_profiles_detection_and_comparison(
    tmp_path, seed, sector, groups
):
    ruleset = load_rules(RULES_DIR)
    detection = detection_of(
        [*ruleset.detections, *ruleset.correlations], (default_attack_data(), default_atlas_data())
    )
    profile = KNOWLEDGE.profile(sector, groups) if sector or groups else None
    result = assess(
        answered(seed), profile=profile, detection=detection, baseline=answered(seed + 10)
    )
    page = tmp_path / "page.html"
    page.write_text(render_html(result), encoding="utf-8", newline="\n")
    harness = tmp_path / "harness.js"
    harness.write_text(HARNESS, encoding="utf-8")
    texts = tmp_path / "texts.json"
    texts.write_text(json.dumps(TEXTS), encoding="utf-8")
    out = subprocess.run(
        [NODE, str(harness), str(page), str(texts)],
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    js = json.loads(out.stdout)
    py = to_dict(result)
    spots = {t.technique.id for t in result.blind_spots}
    for js_fw, py_fw in zip(js["frameworks"], py["frameworks"], strict=True):
        assert js_fw["index"] == py_fw["exposure_index"]
        assert js_fw["counts"] == py_fw["counts"]
        assert js_fw["path"] == [step["technique"] for step in py_fw["path"]]
        assert set(js_fw["blind"]) == spots & set(py_fw["techniques"])
    assert js["priorities"] == [[p["control"], p["relieved"]] for p in py["priorities"]]
    for js_fw, change in zip(js["compare"], py["comparison"]["frameworks"], strict=True):
        assert js_fw["index"] == change["exposure_index"]
        assert js_fw["improved"] == change["improved"]
        assert js_fw["worsened"] == change["worsened"]
    expected = [[[s.mitigation, s.score, list(s.terms)] for s in suggest(t)] for t in TEXTS]
    assert js["suggestions"] == expected
    assert json.loads(render_json(result))["profile"] == py["profile"]
