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
