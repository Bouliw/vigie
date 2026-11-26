import json
import random
import shutil
import subprocess
import zipfile
from datetime import datetime
from pathlib import Path

import pytest

from vigie.assess import questionnaire as q
from vigie.assess.engine import (
    PRE_COMPROMISE,
    assess,
    observed_techniques,
    status_of,
    target_level,
)
from vigie.assess.knowledge import default_knowledge, parent_id
from vigie.assess.questionnaire import Control, Questionnaire, QuestionnaireError
from vigie.assess.render import payload, render_html, render_json, render_markdown, to_dict
from vigie.cli import main
from vigie.demo import DEMO_ASSESSMENT
from vigie.timeutils import UTC

# --- Knowledge base ----------------------------------------------------------------------


def test_knowledge_keeps_techniques_not_sub_techniques():
    kb = default_knowledge()
    attack, atlas = kb.framework("attack"), kb.framework("atlas")
    assert [s.shortname for s in attack.stages][:3] == [
        "reconnaissance",
        "resource-development",
        "initial-access",
    ]
    assert all("." not in t.id for t in attack.techniques)
    assert all(t.id.count(".") == 1 for t in atlas.techniques)
    assert len(attack.techniques) > 150 and len(atlas.techniques) > 50


def test_a_technique_carries_the_mitigations_of_its_sub_techniques():
    kb = default_knowledge()
    brute_force = kb.technique("T1110.003")  # password spraying gives its parent
    assert brute_force.id == "T1110"
    assert "M1032" in brute_force.mitigations
    assert brute_force.weight > 1 and "Used by" in brute_force.prevalence
    injection = kb.technique("AML.T0051.001")
    assert injection.id == "AML.T0051" and "AML.M0020" in injection.mitigations


def test_pre_compromise_is_not_a_preventive_control():
    kb = default_knowledge()
    identity = kb.technique("T1589")  # Gather Victim Identity Information
    assert "M1056" not in identity.mitigations
    assert not identity.preventable


def test_parent_id():
    assert parent_id("T1059.001") == "T1059"
    assert parent_id("aml.t0051.001") == "AML.T0051"
    assert parent_id("AML.T0051") == "AML.T0051"


# --- Questionnaires ---------------------------------------------------------------------


def test_generic_questionnaire_has_one_control_per_preventive_mitigation():
    generic = q.generic()
    kb = default_knowledge()
    ids = {control.id for control in generic.controls}
    assert ids == set(kb.mitigations) - {"M1055", "M1056"}
    assert all(control.mitigations == (control.id,) for control in generic.controls)
    assert generic.answered == 0 and not generic.warnings
    assert len({control.domain for control in generic.controls}) == 10


def test_csv_with_french_headers_semicolons_and_loose_values(tmp_path):
    path = tmp_path / "controles.csv"
    path.write_text(
        "Réf.;Point de contrôle;Domaine;MITRE;Niveau de maturité (0-5);Commentaire\n"
        "PC-01;MFA partout;IAM;M1032, M1036;4;audit 2026\n"
        "PC-02;Correctifs;Vuln;M1051;2,5;\n"
        "PC-03;Garde-fous IA;IA;AML.M0020;n/a;\n"
        "PC-04;Sans mapping;Autre;;3;\n"
        "PC-01;Doublon;IAM;M1018;oui;\n",
        encoding="cp1252",
    )
    loaded = q.load(path)
    assert [c.id for c in loaded.controls] == ["PC-01", "PC-02", "PC-03", "PC-04", "PC-01-6"]
    first = loaded.controls[0]
    assert first.title == "MFA partout" and first.domain == "IAM"
    assert first.mitigations == ("M1032", "M1036") and first.maturity == 4
    assert first.notes == "audit 2026"
    assert loaded.controls[1].maturity == 2.5
    assert loaded.controls[2].maturity is None
    warnings = " ".join(loaded.warnings)
    assert "PC-04 maps to no MITRE mitigation" in warnings
    assert "appears twice" in warnings and "'oui' is not a number" in warnings
    assert loaded.title == "controles"


def test_header_found_below_a_title_row(tmp_path):
    path = tmp_path / "a.csv"
    path.write_text(
        "Audit 2026,,\n,,\nControl,Mitigations,Maturity\nMFA,M1032,1\n", encoding="utf-8"
    )
    assert q.load(path).controls[0].maturity == 1


def _xlsx(path: Path, rows: list[list[str]]) -> None:
    shared: list[str] = []
    sheet_rows = []
    for r, row in enumerate(rows, start=1):
        cells = []
        for c, value in enumerate(row):
            ref = f"{chr(65 + c)}{r}"
            if isinstance(value, (int, float)):
                cells.append(f'<c r="{ref}"><v>{value}</v></c>')
            else:
                shared.append(value)
                cells.append(f'<c r="{ref}" t="s"><v>{len(shared) - 1}</v></c>')
        sheet_rows.append(f'<row r="{r}">{"".join(cells)}</row>')
    main = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    rel = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(
            "xl/workbook.xml",
            f'<workbook xmlns="{main}" xmlns:r="{rel}"><sheets>'
            '<sheet name="Answers" sheetId="1" r:id="rId1"/></sheets></workbook>',
        )
        z.writestr(
            "xl/_rels/workbook.xml.rels",
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Target="worksheets/answers.xml" Type="x"/></Relationships>',
        )
        z.writestr(
            "xl/sharedStrings.xml",
            f'<sst xmlns="{main}">' + "".join(f"<si><t>{s}</t></si>" for s in shared) + "</sst>",
        )
        z.writestr(
            "xl/worksheets/answers.xml",
            f'<worksheet xmlns="{main}"><sheetData>{"".join(sheet_rows)}</sheetData></worksheet>',
        )


def test_excel_workbook(tmp_path):
    path = tmp_path / "answers.xlsx"
    _xlsx(
        path,
        [
            ["ID", "Control", "MITRE mitigations", "Techniques", "Maturity"],
            ["A1", "MFA", "M1032", "", 3.0],
            ["A2", "Guardrails", "AML.M0020", "AML.T0051.001", 1],
        ],
    )
    loaded = q.load(path)
    assert [(c.id, c.maturity) for c in loaded.controls] == [("A1", 3), ("A2", 1)]
    assert loaded.controls[1].techniques == ("AML.T0051.001",)


def test_json_questionnaire_with_its_scale(tmp_path):
    path = tmp_path / "answers.json"
    path.write_text(
        json.dumps(
            {
                "title": "Audit",
                "scale": 4,
                "controls": [{"id": "X", "control": "MFA", "mitigations": ["M1032"], "level": 4}],
            }
        ),
        encoding="utf-8",
    )
    loaded = q.load(path)
    assert loaded.scale == 4 and loaded.title == "Audit"
    assert loaded.controls[0].maturity == 4


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("Control,Maturity\nMFA,1\n", "no column maps the controls to MITRE"),
        ("Maturity,Mitigations\n1,M1032\n", "no column names a control"),
        ("Control,Mitigations,Maturity\nMFA,M1032,7\n", "above the default 0-5 scale"),
        ("Control,Mitigations,Maturity\n", "no control found"),
    ],
)
def test_unreadable_questionnaires(tmp_path, text, message):
    path = tmp_path / "bad.csv"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(QuestionnaireError, match=message):
        q.load(path)


def test_wrong_file_kinds(tmp_path):
    with pytest.raises(QuestionnaireError, match="no such file"):
        q.load(tmp_path / "none.csv")
    (tmp_path / "a.pdf").write_bytes(b"%PDF")
    with pytest.raises(QuestionnaireError, match=r"use a \.csv"):
        q.load(tmp_path / "a.pdf")
    (tmp_path / "a.xlsx").write_bytes(b"not a zip")
    with pytest.raises(QuestionnaireError, match="not an Excel"):
        q.load(tmp_path / "a.xlsx")


def test_a_larger_scale(tmp_path):
    path = tmp_path / "a.csv"
    path.write_text("Control,Mitigations,Maturity\nMFA,M1032,80\nTLS,M1020,120\n", "utf-8")
    loaded = q.load(path, scale=100)
    assert loaded.controls[0].maturity == 80 and loaded.controls[1].maturity is None
    assert "outside 0-100" in loaded.warnings[0]
    assert q.level_names(100)[42] == "42"


def test_csv_round_trip():
    generic = q.generic().with_answers({"M1032": 4, "AML.M0020": 1})
    again = q.parse_csv(q.to_csv(generic))
    assert [(c.id, c.maturity) for c in again.controls] == [
        (c.id, c.maturity) for c in generic.controls
    ]


# --- Engine -----------------------------------------------------------------------------


def _questionnaire(*controls: Control, scale: int = 5) -> Questionnaire:
    return Questionnaire(list(controls), scale=scale, title="test")


def _technique(assessment, technique_id):
    for result in assessment.frameworks:
        for stage in result.stages:
            for technique in stage.techniques:
                if technique.technique.id == technique_id:
                    return technique
    raise KeyError(technique_id)


def test_status_thresholds():
    assert [status_of(level, 5) for level in (None, 0, 1, 2, 3, 4, 5)] == [
        "unassessed",
        "facilitated",
        "facilitated",
        "partial",
        "partial",
        "hindered",
        "hindered",
    ]
    assert target_level(5) == 4 and target_level(4) == 4 and target_level(10) == 8


def test_the_strongest_mitigation_decides():
    result = assess(
        _questionnaire(
            Control("a", "MFA", mitigations=("M1032",), maturity=1),
            Control("b", "Accounts", mitigations=("M1036",), maturity=4),
        )
    )
    valid_accounts = _technique(result, "T1078")
    assert valid_accounts.level == 4 and valid_accounts.status == "hindered"
    assert set(valid_accounts.controls) == {"a", "b"}
    assert "M1032" not in valid_accounts.uncovered
    untouched = _technique(result, "T1566")  # Phishing, none of its mitigations rated
    assert untouched.status == "unassessed" and untouched.exposure is None


def test_a_control_can_counter_a_technique_directly():
    result = assess(_questionnaire(Control("x", "Sandbox", techniques=("T1059.001",), maturity=0)))
    interpreter = _technique(result, "T1059")
    assert interpreter.status == "facilitated" and interpreter.controls == ("x",)


def test_unpreventable_techniques_stay_open():
    result = assess(_questionnaire(*[Control(m, m, mitigations=(m,), maturity=5) for m in "M1056"]))
    assert _technique(result, "T1589").status == "unpreventable"
    assert _technique(result, "T1589").exposure == 1.0


def test_full_maturity_blocks_the_easiest_path():
    generic = q.generic()
    best = generic.with_answers({c.id: 5 for c in generic.controls})
    result = assess(best)
    for framework in result.frameworks:
        assert framework.exposure_index == 0
        assert framework.counts["facilitated"] == framework.counts["partial"] == 0
        if framework.blocked_at:
            path = framework.path
            assert path[-1].stage.shortname == framework.blocked_at
            assert path[-1].status == "hindered"
            assert all(s.status == "unpreventable" for s in path[:-1])
    assert result.priorities == []


def test_no_maturity_opens_everything_and_ranks_priorities():
    generic = q.generic()
    worst = generic.with_answers({c.id: 0 for c in generic.controls})
    result = assess(worst)
    attack = result.framework("attack")
    assert attack.exposure_index == 100 and attack.blocked_at is None
    assert attack.counts["partial"] == attack.counts["hindered"] == 0
    assert len(result.priorities) == 12
    gains = [p.gain for p in result.priorities]
    assert gains == sorted(gains, reverse=True)
    assert all(p.target == 4 for p in result.priorities)


def test_pre_compromise_techniques_count_half_in_priorities():
    kb = default_knowledge()
    recon_only = [
        t
        for t in kb.framework("atlas").techniques
        if t.mitigations and set(t.stages) <= PRE_COMPROMISE
    ]
    technique = recon_only[0]
    mitigation = technique.mitigations[0]
    result = assess(_questionnaire(Control("c", "x", mitigations=(mitigation,), maturity=0)))
    priority = result.priorities[0]
    path = {s.step.technique.id for f in result.frameworks for s in f.path if s.step}
    full = sum(
        _technique(result, t).technique.weight
        * (2 if t in path else 1)
        * (0.5 if set(_technique(result, t).technique.stages) <= PRE_COMPROMISE else 1)
        for t in priority.relieved
    )
    assert priority.gain == pytest.approx(full, abs=1e-3)


def test_alerts_seen_in_the_logs_are_crossed():
    result = assess(
        _questionnaire(Control("m", "MFA", mitigations=("M1032",), maturity=0)),
        observed={"T1110.001": 2, "T1110.003": 1, "AML.T0051": 4},
    )
    assert result.observed == {"T1110": 3, "AML.T0051": 4}
    brute_force = _technique(result, "T1110")
    assert brute_force.observed == 3 and brute_force.status == "facilitated"
    assert [t.technique.id for t in result.observed_open] == ["T1110"]
    assert result.priorities[0].observed >= 1


def test_unknown_ids_are_reported():
    unknown = Control("z", "?", mitigations=("M9999",), techniques=("T9999",))
    result = assess(_questionnaire(unknown))
    assert result.unknown_ids == ["M9999", "T9999"]


def test_observed_techniques_from_report_alerts():
    from vigie.analysis import analyze
    from vigie.report.builder import build_report

    fixture = Path(__file__).parent / "fixtures" / "authlog" / "auth.log"
    report = build_report(analyze(fixture, year=2024), generated_at=datetime.now(UTC))
    counts = observed_techniques(report.alerts)
    assert counts and all(isinstance(v, int) and v > 0 for v in counts.values())
    assert "T1110.001" in counts


# --- Rendering --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def demo_assessment():
    observed = {"T1110.001": 3, "AML.T0051.001": 2, "T1129": 1}
    return assess(q.load(DEMO_ASSESSMENT), observed=observed)


def test_html_embeds_what_the_page_computes_from(demo_assessment):
    html = render_html(demo_assessment)
    data = json.loads(html.split('id="vigie-data">')[1].split("</script>")[0])
    assert data["meta"]["scale"] == 5 and len(data["controls"]) == 86
    assert {f["key"] for f in data["frameworks"]} == {"attack", "atlas"}
    assert data["observed"] == {"AML.T0051": 2, "T1110": 3, "T1129": 1}
    assert 'http-equiv="Content-Security-Policy"' in html
    assert "<script src" not in html and "https://fonts" not in html


def test_markdown_and_json(demo_assessment):
    md = render_markdown(demo_assessment)
    assert "## MITRE ATT&CK 19.2 (Enterprise)" in md and "## What to raise first" in md
    assert "Seen in the logs and left open" in md
    data = json.loads(render_json(demo_assessment))
    assert data["controls"] == {"total": 86, "answered": 86}
    assert [f["key"] for f in data["frameworks"]] == ["attack", "atlas"]
    assert data["frameworks"][0]["path"][0]["stage"] == "Reconnaissance"


def test_page_text_is_escaped(tmp_path):
    title = "</script><script>alert(1)</script>"
    hostile = Control("<x>", title, mitigations=("M1032",), maturity=1)
    html = render_html(assess(_questionnaire(hostile)))
    assert "</script><script>alert(1)" not in html


# --- The page computes the same thing as Python ------------------------------------------

NODE = shutil.which("node")
HARNESS = """
const fs = require("fs");
const html = fs.readFileSync(process.argv[2], "utf8");
const data = html.split('id="vigie-data">')[1].split("</script>")[0];
const script = html.split(/<script>\\r?\\n/).pop().split("</script>")[0];
const window = { __vigieAssessTest: function (api) {
  const r = api.compute(api.DATA.controls);
  const out = {
    frameworks: r.frameworks.map(f => ({
      key: f.fw.key, index: f.index, counts: f.counts, blocked: f.blockedAt,
      path: f.path.map(s => s.step ? s.step.t.id : null),
      statuses: Object.fromEntries(f.evaluated.map(e => [e.t.id, e.status]))
    })),
    priorities: r.priorities.map(p => [p.control.id, p.relieved]),
    open: r.observedOpen.map(e => e.t.id)
  };
  process.stdout.write(JSON.stringify(out));
} };
const document = { getElementById: () => ({ textContent: data }) };
new Function("window", "document", script)(window, document);
"""


@pytest.mark.skipif(NODE is None, reason="needs Node.js")
@pytest.mark.parametrize("seed", [1, 2, 3, 4])
def test_the_page_and_python_agree(tmp_path, seed):
    rng = random.Random(seed)
    generic = q.generic()
    answers = {c.id: rng.choice([None, 0, 1, 2, 3, 4, 5, 2.5]) for c in generic.controls}
    questionnaire = generic.with_answers(answers)
    observed = {"T1110.001": 2, "T1078": 1, "AML.T0051.001": 1, "T1059.001": 4}
    result = assess(questionnaire, observed=observed)
    page = tmp_path / "page.html"
    page.write_text(render_html(result), encoding="utf-8", newline="\n")
    harness = tmp_path / "harness.js"
    harness.write_text(HARNESS, encoding="utf-8")
    out = subprocess.run(
        [NODE, str(harness), str(page)], capture_output=True, text=True, check=True, timeout=60
    )
    js = json.loads(out.stdout)
    py = to_dict(result)
    for js_fw, py_fw in zip(js["frameworks"], py["frameworks"], strict=True):
        assert js_fw["index"] == py_fw["exposure_index"]
        assert js_fw["counts"] == py_fw["counts"]
        assert js_fw["blocked"] == py_fw["blocked_at"]
        assert js_fw["path"] == [step["technique"] for step in py_fw["path"]]
        assert js_fw["statuses"] == {k: v["status"] for k, v in py_fw["techniques"].items()}
    assert js["priorities"] == [[p["control"], p["relieved"]] for p in py["priorities"]]
    assert js["open"] == py["observed_open"]


def test_payload_lists_the_column_names_the_page_understands():
    data = payload(q.generic())
    assert data["meta"]["columns"]["maturity"][0] == "maturity"
    assert data["meta"]["levels"][4] == "Managed"


# --- Command line -----------------------------------------------------------------------


def test_cli_template_then_assessment(tmp_path, capsys):
    template = tmp_path / "answers.csv"
    assert main(["assess", "--template", str(template)]) == 0
    text = template.read_text(encoding="utf-8-sig")
    assert text.startswith("id,domain,control,description,mitigations,techniques,maturity,notes")
    filled = text.replace("M1032,,,", "M1032,,1,", 1)
    template.write_text(filled, encoding="utf-8")
    out = tmp_path / "out"
    args = ["assess", str(template), "-o", str(out), "--no-open", "--format", "html,md,json"]
    assert main(args) == 0
    assert sorted(p.name for p in out.iterdir()) == [
        "assessment.html",
        "assessment.json",
        "assessment.md",
    ]
    stdout = capsys.readouterr().out
    assert "1 of 86 controls answered" in stdout and "MITRE ATT&CK: exposure" in stdout


def test_cli_json_template(tmp_path):
    template = tmp_path / "answers.json"
    assert main(["assess", "--template", str(template)]) == 0
    loaded = q.load(template)
    assert len(loaded.controls) == 86 and loaded.answered == 0


def test_cli_demo_crosses_the_sample_logs(tmp_path, capsys):
    out = tmp_path / "demo"
    args = ["assess", "--demo", "-o", str(out), "--no-open", "--format", "json", "--plain"]
    assert main(args) == 0
    data = json.loads((out / "assessment.json").read_text(encoding="utf-8"))
    assert data["title"] == "Sample organization (demo)"
    assert data["observed"] and data["observed_open"]
    assert "technique(s) the maturity leaves open" in capsys.readouterr().out


def test_cli_reports_a_bad_questionnaire(tmp_path, capsys):
    bad = tmp_path / "bad.csv"
    bad.write_text("Control,Maturity\nMFA,1\n", encoding="utf-8")
    assert main(["assess", str(bad), "-o", str(tmp_path / "o"), "--no-open"]) == 2
    assert "no column maps the controls to MITRE" in capsys.readouterr().err


def test_cli_rejects_a_bad_scale(tmp_path, capsys):
    assert main(["assess", "--scale", "0", "-o", str(tmp_path / "o"), "--no-open"]) == 2
    assert "scale must be between" in capsys.readouterr().err
