"""Run the installed command on the whole fixture folder, as a user would."""

import json
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).parent
CASES = yaml.safe_load((ROOT / "rules" / "cases.yaml").read_text(encoding="utf-8"))
FEEDERS = {
    "73004885-6e82-4146-ab6a-1b834d099ee5",
    "118338f6-e0cd-41d4-bfdf-58a76f7ba286",
    "0ca0b8d2-4007-47d0-81ec-8c96d0fc2cf1",
    "e9ae903d-6632-4e89-beea-4da9d26a99af",
    "4238e8b1-56d6-4fd4-b6f9-bbf4c9077911",
    "58dc991d-93ea-434e-ae77-b62daf019a03",
}


def test_vigie_analyze_on_all_fixtures(tmp_path):
    out = tmp_path / "report"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "vigie",
            "analyze",
            str(ROOT / "fixtures"),
            "-o",
            str(out),
            "--format",
            "html,md,json",
            "--min-level",
            "informational",
            "--year",
            "2024",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stderr == ""
    assert "Report:" in completed.stdout

    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert data["rule_errors"] == []
    assert all(report["events"] > 0 for report in data["files"])
    fired = {alert["rule"]["id"] for alert in data["alerts"]}
    # Every rule with a positive fixture raises an alert, except those that only
    # feed correlations.
    expected = {case["rule"] for case in CASES} - FEEDERS
    assert fired == expected

    html = (out / "report.html").read_text(encoding="utf-8")
    markdown = (out / "report.md").read_text(encoding="utf-8")
    for alert in data["alerts"]:
        assert alert["rule"]["title"] in html
        assert alert["rule"]["title"] in markdown


def test_progress_reports_without_changing_results():
    from vigie.analysis import analyze

    calls = []
    folder = ROOT / "fixtures" / "authlog"
    with_progress = analyze(folder, year=2024, progress=lambda stage, **d: calls.append((stage, d)))
    plain = analyze(folder, year=2024)
    stages = [stage for stage, _ in calls]
    assert stages[0] == "file" and stages[-1] == "done"
    files = [d for stage, d in calls if stage == "file"]
    assert [d["index"] for d in files] == list(range(len(files)))
    assert files[0]["total"] == len(files) == len(plain.collection.files)
    parsed = [d["events"] for stage, d in calls if stage == "parsed"]
    assert parsed == sorted(parsed) and parsed[-1] == len(plain.collection.events)
    matched = [d for stage, d in calls if stage == "match"]
    assert matched[-1] == {
        "done": len(plain.collection.events),
        "total": len(plain.collection.events),
    }
    assert calls[-1][1]["alerts"] == len(plain.evaluation.alerts)
    assert [a.rule.id for a in with_progress.evaluation.alerts] == [
        a.rule.id for a in plain.evaluation.alerts
    ]
