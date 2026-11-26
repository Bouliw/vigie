"""Build the generic questionnaire `vigie assess` offers: one control per MITRE mitigation.

Each preventive mitigation of MITRE ATT&CK Enterprise and MITRE ATLAS becomes a
control, grouped in domains a security team recognizes, with the mitigation's
own summary as description. The maturity column is left empty, to be filled
in. The result is ``src/vigie/assess/data/questionnaire.csv``.

Usage::

    python tools/build_questionnaire.py

Run it after updating the ATT&CK or ATLAS extracts (``build_attack_data.py``,
``build_atlas_data.py``). Mitigations missing from DOMAINS stop the script, so a
new MITRE mitigation is never left out silently.
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "src" / "vigie"
OUTPUT = ROOT / "assess" / "data" / "questionnaire.csv"
# Not preventive controls: "Do Not Mitigate" and "Pre-compromise".
SKIPPED = {"M1055", "M1056"}

DOMAINS = {
    "Identity and access": [
        "M1015",
        "M1018",
        "M1026",
        "M1027",
        "M1032",
        "M1036",
        "M1043",
        "M1052",
    ],
    "Endpoint and system hardening": [
        "M1022",
        "M1024",
        "M1025",
        "M1028",
        "M1033",
        "M1034",
        "M1038",
        "M1039",
        "M1040",
        "M1042",
        "M1044",
        "M1045",
        "M1046",
        "M1048",
        "M1049",
        "M1050",
        "M1054",
    ],
    "Network": ["M1020", "M1021", "M1030", "M1031", "M1035", "M1037", "M1060"],
    "Vulnerabilities and secure development": ["M1013", "M1016", "M1051"],
    "Data protection and recovery": ["M1029", "M1041", "M1053", "M1057"],
    "Monitoring, threat intelligence and people": ["M1017", "M1019", "M1047"],
    "AI governance and supply chain": [
        "AML.M0000",
        "AML.M0001",
        "AML.M0011",
        "AML.M0013",
        "AML.M0014",
        "AML.M0016",
        "AML.M0017",
        "AML.M0018",
        "AML.M0023",
        "AML.M0025",
        "AML.M0035",
        "AML.M0042",
        "AML.M0043",
    ],
    "AI model and data protection": [
        "AML.M0002",
        "AML.M0003",
        "AML.M0006",
        "AML.M0007",
        "AML.M0008",
        "AML.M0009",
        "AML.M0010",
        "AML.M0015",
        "AML.M0020",
        "AML.M0021",
        "AML.M0022",
        "AML.M0031",
        "AML.M0034",
        "AML.M0039",
        "AML.M0040",
        "AML.M0041",
    ],
    "AI access and usage": [
        "AML.M0004",
        "AML.M0005",
        "AML.M0012",
        "AML.M0019",
        "AML.M0024",
        "AML.M0036",
    ],
    "AI agents": [
        "AML.M0026",
        "AML.M0027",
        "AML.M0028",
        "AML.M0029",
        "AML.M0030",
        "AML.M0032",
        "AML.M0033",
        "AML.M0037",
        "AML.M0038",
    ],
}


def main() -> int:
    attack = json.loads((ROOT / "attack" / "data" / "enterprise_attack.json").read_text("utf-8"))
    atlas = json.loads((ROOT / "atlas" / "data" / "atlas.json").read_text("utf-8"))
    mitigations = attack["mitigations"] | atlas["mitigations"]
    placed = [m for ids in DOMAINS.values() for m in ids]
    missing = sorted(set(mitigations) - set(placed) - SKIPPED)
    unknown = sorted(set(placed) - set(mitigations))
    if missing or unknown:
        print(f"missing from DOMAINS: {missing}; not in the data: {unknown}", file=sys.stderr)
        return 1
    rows = [["id", "domain", "control", "description", "mitigations", "maturity", "notes"]]
    for domain, ids in DOMAINS.items():
        for mitigation_id in ids:
            entry = mitigations[mitigation_id]
            summary = entry.get("summary", "")
            rows.append([mitigation_id, domain, entry["name"], summary, mitigation_id, "", ""])
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("w", encoding="utf-8", newline="") as handle:
        csv.writer(handle, lineterminator="\n").writerows(rows)
    print(f"{len(rows) - 1} controls -> {OUTPUT}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
