"""Build Vigie's MITRE ATT&CK extract from the official STIX bundle.

The full Enterprise ATT&CK bundle is about 54 MB. Vigie only needs, for each
tactic and technique, its name, tactics, URL and a one or two sentence summary
of its description (shown in the HTML report), the mitigations MITRE lists
against it and how many known groups, campaigns and pieces of software use it
(for ``vigie assess``), for each mitigation its name and summary, and for each
group the techniques it uses and the sectors its description names (the threat
profiles of ``vigie assess``). This script keeps just that (about 500 KB) in
``src/vigie/attack/data/enterprise_attack.json``.

Usage::

    python tools/build_attack_data.py                 # latest release
    python tools/build_attack_data.py --version 19.2  # a given release
    python tools/build_attack_data.py --input enterprise-attack-19.2.json

Only the standard library is used, so the script runs without installing Vigie.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path
from typing import Any

STIX_REPO = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
INDEX_URL = f"{STIX_REPO}/index.json"
OUTPUT = Path(__file__).resolve().parent.parent / "src" / "vigie" / "attack" / "data"
COPYRIGHT = (
    "© {year} The MITRE Corporation. This work is reproduced and distributed "
    "with the permission of The MITRE Corporation."
)
SUMMARY_LENGTH = 320  # characters: a sentence or two, enough to say what a technique is

# Sectors a group's ATT&CK description names, found with these expressions (case
# ignored, whole words). ATT&CK has no structured sector field: this is a reading
# of MITRE's own words, shown as such to the user.
SECTORS = {
    "healthcare": (
        "Healthcare and life sciences",
        r"health ?care|hospitals?|medical|pharmaceuticals?|biotech\w*|life sciences|biomedical"
        r"|vaccines?",
    ),
    "financial": (
        "Banking, finance and insurance",
        r"banks?|banking|financial|finance|insurance|fintech|cryptocurrenc\w+|payments?",
    ),
    "government": (
        "Government and public sector",
        r"government\w*|ministr\w+|embass\w+|diplomat\w*|public sector|municipal\w*",
    ),
    "defense": (
        "Defense and aerospace",
        r"defen[cs]e (?:sector|industr\w*|contractors?|organizations?)|military|aerospace"
        r"|armed forces",
    ),
    "energy": (
        "Energy and utilities",
        r"energy|oil|natural gas|electric\w*|utilit(?:y|ies)|nuclear|power (?:grid|plants?)"
        r"|petroleum|petrochemical",
    ),
    "industry": (
        "Manufacturing and industry",
        r"manufactur\w+|industrial(?! espionage)|(?<!social )(?<!reverse )engineering"
        r"|automotive|chemical(?! weapons)|construction",
    ),
    "telecom": ("Telecommunications", r"telecom\w*"),
    "technology": (
        "Technology and IT services",
        r"technology (?:companies|firms|sector|organizations)|information technology"
        r"|software (?:companies|vendors|developers)|semiconductor\w*"
        r"|managed (?:IT )?service providers?|IT (?:companies|service providers|sector)"
        r"|cloud providers?|high[- ]tech",
    ),
    "education": (
        "Education and research",
        r"education\w*|universit(?:y|ies)|academ\w+|research (?:institut\w+|centers?|organizations)"
        r"|think tanks?",
    ),
    "retail": (
        "Retail and hospitality",
        r"retail\w*|hospitality|restaurants?|hotels?|point[- ]of[- ]sale|e-?commerce",
    ),
    "media": (
        "Media and entertainment",
        r"(?<!social )media|journalists?|news|entertainment|gaming|video games?",
    ),
    "transport": (
        "Transport and logistics",
        r"transport\w*|logistics|aviation|airlines?|maritime|shipping",
    ),
    "legal": ("Legal and professional services", r"law firms?|legal|professional services"),
    "civil-society": (
        "NGOs and civil society",
        r"non-?governmental|NGOs?|dissidents?|activists?|human rights|civil society",
    ),
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--version", help="ATT&CK release, e.g. 19.2 (default: latest)")
    source.add_argument("--input", type=Path, help="local enterprise-attack STIX bundle")
    parser.add_argument("--output", type=Path, default=OUTPUT / "enterprise_attack.json")
    args = parser.parse_args(argv)

    if args.input:
        bundle, url = json.loads(args.input.read_text(encoding="utf-8")), str(args.input.name)
    else:
        version = args.version or latest_version()
        url = f"{STIX_REPO}/enterprise-attack/enterprise-attack-{version}.json"
        print(f"downloading {url}", file=sys.stderr)
        bundle = fetch_json(url)

    data = extract(bundle, url)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(
        f"ATT&CK {data['attack_version']}: {len(data['tactics'])} tactics, "
        f"{len(data['techniques'])} techniques, {len(data['mitigations'])} mitigations, "
        f"{len(data['revoked'])} revoked ids, {len(data['groups'])} groups "
        f"-> {args.output}",
        file=sys.stderr,
    )
    return 0


def fetch_json(url: str) -> Any:
    with urllib.request.urlopen(url, timeout=120) as response:
        return json.load(response)


def latest_version() -> str:
    index = fetch_json(INDEX_URL)
    for collection in index["collections"]:
        if collection["name"] == "Enterprise ATT&CK":
            return str(collection["versions"][0]["version"])
    raise SystemExit("Enterprise ATT&CK not found in the STIX index")


def extract(bundle: dict[str, Any], source: str) -> dict[str, Any]:
    objects = bundle["objects"]
    by_id = {obj["id"]: obj for obj in objects}
    collection = next(obj for obj in objects if obj["type"] == "x-mitre-collection")
    matrix = next(obj for obj in objects if obj["type"] == "x-mitre-matrix")

    # Tactics in matrix order (Reconnaissance ... Impact), for sorting reports.
    tactics = []
    for ref in matrix["tactic_refs"]:
        tactic = by_id[ref]
        tactics.append(
            {
                "id": attack_id(tactic),
                "shortname": tactic["x_mitre_shortname"],
                "name": tactic["name"],
                "url": attack_url(tactic),
                **with_summary(tactic),
            }
        )

    techniques = {}
    for obj in objects:
        if obj["type"] != "attack-pattern" or not is_active(obj):
            continue
        technique_id = attack_id(obj)
        techniques[technique_id] = {
            "name": obj["name"],
            "tactics": [
                phase["phase_name"]
                for phase in obj.get("kill_chain_phases", [])
                if phase["kill_chain_name"] == "mitre-attack"
            ],
            "url": attack_url(obj),
            **with_summary(obj),
        }

    # Older rules still use revoked ids (e.g. T1086 -> T1059.001).
    revoked = {}
    for obj in objects:
        if obj["type"] == "relationship" and obj["relationship_type"] == "revoked-by":
            old, new = by_id.get(obj["source_ref"]), by_id.get(obj["target_ref"])
            if old and new and old["type"] == "attack-pattern" and attack_id(new) in techniques:
                revoked[attack_id(old)] = attack_id(new)

    # Mitigations (M1032 Multi-factor Authentication...) and the techniques each one
    # mitigates, for `vigie assess`. The old technique-specific courses of action
    # (T1003-style ids) are deprecated and left out.
    mitigations = {}
    for obj in objects:
        if obj["type"] == "course-of-action" and is_active(obj):
            mitigation_id = attack_id(obj)
            if re.fullmatch(r"M\d{4}", mitigation_id):
                summary = complete_sentences(with_summary(obj).get("summary", ""))
                mitigations[mitigation_id] = {
                    "name": obj["name"],
                    "url": attack_url(obj),
                    **({"summary": summary} if summary else {}),
                }
    mitigated_by: dict[str, set[str]] = {}
    used_by: dict[str, set[str]] = {}
    users = {"intrusion-set", "campaign", "malware", "tool"}
    for obj in objects:
        if obj["type"] != "relationship" or not is_active(obj):
            continue
        actor, target = by_id.get(obj["source_ref"]), by_id.get(obj["target_ref"])
        if not actor or not target or target["type"] != "attack-pattern" or not is_active(actor):
            continue
        technique_id = attack_id(target)
        if technique_id not in techniques:
            continue
        if obj["relationship_type"] == "mitigates" and actor["type"] == "course-of-action":
            mitigation_id = attack_id(actor)
            if mitigation_id in mitigations:
                mitigated_by.setdefault(technique_id, set()).add(mitigation_id)
        elif obj["relationship_type"] == "uses" and actor["type"] in users:
            used_by.setdefault(technique_id, set()).add(actor["id"])
    # A technique counts the users of its sub-techniques too: a group seen using
    # T1059.001 (PowerShell) uses T1059 (Command and Scripting Interpreter).
    for technique_id in list(used_by):
        if "." in technique_id:
            parent = technique_id.split(".")[0]
            used_by.setdefault(parent, set()).update(used_by[technique_id])
    for technique_id, entry in techniques.items():
        entry["mitigations"] = sorted(mitigated_by.get(technique_id, ()))
        entry["used_by"] = len(used_by.get(technique_id, ()))

    groups = extract_groups(objects, by_id, techniques)

    modified = collection["modified"]
    return {
        "attack_version": collection["x_mitre_version"],
        "modified": modified,
        "source": source,
        "copyright": COPYRIGHT.format(year=modified[:4]),
        "tactics": tactics,
        "techniques": dict(sorted(techniques.items())),
        "mitigations": dict(sorted(mitigations.items())),
        "revoked": dict(sorted(revoked.items())),
        "sectors": {key: label for key, (label, _) in SECTORS.items()},
        "groups": groups,
    }


def extract_groups(
    objects: list[dict[str, Any]], by_id: dict[str, Any], techniques: dict[str, Any]
) -> dict[str, Any]:
    """Each group (G0016...), the techniques it uses and the sectors it targets.

    A group uses the techniques MITRE relates to it directly and those of the
    campaigns attributed to it. Sub-techniques count as their parent technique.
    """
    campaigns: dict[str, set[str]] = {}
    for obj in objects:
        if obj["type"] == "relationship" and obj["relationship_type"] == "attributed-to":
            campaign, group = by_id.get(obj["source_ref"]), by_id.get(obj["target_ref"])
            if campaign and group and campaign["type"] == "campaign" and is_active(campaign):
                campaigns.setdefault(group["id"], set()).add(campaign["id"])
    uses: dict[str, set[str]] = {}
    for obj in objects:
        if obj["type"] != "relationship" or obj["relationship_type"] != "uses":
            continue
        if not is_active(obj):
            continue
        target = by_id.get(obj["target_ref"])
        if not target or target["type"] != "attack-pattern" or not is_active(target):
            continue
        technique_id = attack_id(target).split(".")[0]
        if technique_id in techniques:
            uses.setdefault(obj["source_ref"], set()).add(technique_id)
    groups = {}
    for obj in objects:
        if obj["type"] != "intrusion-set" or not is_active(obj):
            continue
        used = set(uses.get(obj["id"], ()))
        for campaign_id in campaigns.get(obj["id"], ()):
            used |= uses.get(campaign_id, set())
        if not used:
            continue
        groups[attack_id(obj)] = {
            "name": obj["name"],
            "aliases": [alias for alias in obj.get("aliases", []) if alias != obj["name"]],
            "url": attack_url(obj),
            "sectors": sectors_of(obj.get("description", "")),
            "techniques": sorted(used),
        }
    return dict(sorted(groups.items()))


def sectors_of(description: str) -> list[str]:
    text = re.sub(r"\(Citation:[^)]*\)", " ", description)
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    return [
        key
        for key, (_, pattern) in SECTORS.items()
        if re.search(r"\b(?:" + pattern + r")\b", text, re.IGNORECASE)
    ]


def with_summary(obj: dict[str, Any]) -> dict[str, str]:
    """``{"summary": ...}`` for an object with a description, ``{}`` otherwise."""
    text = summarize(obj.get("description", ""))
    return {"summary": text} if text else {}


def summarize(description: str) -> str:
    """The first sentences of a description, as plain text, up to SUMMARY_LENGTH characters.

    ATT&CK descriptions are Markdown with citations: links keep their text,
    ``(Citation: ...)`` markers and HTML tags are dropped.
    """
    paragraph = description.strip().split("\n\n")[0]
    paragraph = re.sub(r"\(Citation:[^)]*\)", "", paragraph)
    paragraph = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", paragraph)
    paragraph = re.sub(r"<[^>]+>", "", paragraph)
    paragraph = " ".join(paragraph.split())
    sentences = re.split(r"(?<=[.!?])\s+(?=[A-Z(])", paragraph)
    # "e.g." or "i.e." end no sentence.
    merged: list[str] = []
    for sentence in sentences:
        if merged and re.search(r"\b(?:e\.g|i\.e|vs|Inc|Ltd)\.$", merged[-1]):
            merged[-1] += " " + sentence
        else:
            merged.append(sentence)
    text = ""
    for sentence in merged:
        if text and len(text) + 1 + len(sentence) > SUMMARY_LENGTH:
            break
        text = f"{text} {sentence}".strip()
    if len(text) > SUMMARY_LENGTH:
        text = text[: SUMMARY_LENGTH - 1].rsplit(" ", 1)[0] + "…"
    return text


def complete_sentences(summary: str) -> str:
    """Drop a last sentence that only introduces a list ("These factors include:")."""
    sentences = re.split(r"(?<=[.!?])\s+", summary)
    while len(sentences) > 1 and sentences[-1].rstrip().endswith(":"):
        sentences.pop()
    return " ".join(sentences)


def is_active(obj: dict[str, Any]) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def mitre_reference(obj: dict[str, Any]) -> dict[str, Any]:
    return next(r for r in obj["external_references"] if r.get("source_name") == "mitre-attack")


def attack_id(obj: dict[str, Any]) -> str:
    return str(mitre_reference(obj)["external_id"])


def attack_url(obj: dict[str, Any]) -> str:
    return str(mitre_reference(obj)["url"])


if __name__ == "__main__":
    raise SystemExit(main())
