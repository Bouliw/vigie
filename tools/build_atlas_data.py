"""Build Vigie's MITRE ATLAS extract from the official ATLAS data.

MITRE ATLAS is the ATT&CK-style knowledge base of attacks on AI systems. Its
data is published as one YAML file per release (about 1 MB) in
mitre-atlas/atlas-data. Vigie needs, for each tactic and technique, its id,
name, tactics, URL and a one or two sentence summary of its description, and
for the "ATLAS context" of an alert: the description as plain text, the
maturity, the mitigations with what each one does against the technique, the
related techniques and the case studies that employ it. This script keeps
just that in ``src/vigie/atlas/data/atlas.json``.

Usage::

    python tools/build_atlas_data.py                    # latest release
    python tools/build_atlas_data.py --version 2026.09  # a given release
    python tools/build_atlas_data.py --input ATLAS-2026.09.yaml

The data is read in the ATLAS format 6 (``dist/v6/``); ``dist/ATLAS.yaml``, the
older format, is no longer updated. The script needs PyYAML, which Vigie
already depends on.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

DATA_REPO = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist"
MANIFEST_URL = f"{DATA_REPO}/manifest.yaml"
SITE = "https://atlas.mitre.org"
FORMAT = 6  # major version of the ATLAS data format this script reads
OUTPUT = Path(__file__).resolve().parent.parent / "src" / "vigie" / "atlas" / "data"
COPYRIGHT = (
    "MITRE ATLAS data: Copyright 2021-{year} MITRE, licensed under the Apache License, Version 2.0."
)
SUMMARY_LENGTH = 320  # characters: a sentence or two, enough to say what a technique is
RELATED_BY_CASE = 3  # techniques most often employed in the same case studies


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--version", help="ATLAS release, e.g. 2026.09 (default: latest)")
    source.add_argument("--input", type=Path, help="local ATLAS YAML file (format 6)")
    parser.add_argument("--output", type=Path, default=OUTPUT / "atlas.json")
    args = parser.parse_args(argv)

    if args.input:
        text, url = args.input.read_text(encoding="utf-8"), args.input.name
    else:
        url = f"{DATA_REPO}/{release_path(fetch_text(MANIFEST_URL), args.version)}"
        print(f"downloading {url}", file=sys.stderr)
        text = fetch_text(url)

    data = extract(yaml.safe_load(text), url)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(
        f"ATLAS {data['atlas_version']}: {len(data['tactics'])} tactics, "
        f"{len(data['techniques'])} techniques -> {args.output}",
        file=sys.stderr,
    )
    return 0


def fetch_text(url: str) -> str:
    with urllib.request.urlopen(url, timeout=120) as response:
        return response.read().decode("utf-8")


def release_path(manifest_text: str, version: str | None) -> str:
    """Path, under ``dist/``, of a release (the latest by default) in the supported format.

    The manifest lists releases newest first. ``dist/ATLAS-latest.yaml`` is a
    symbolic link, which raw.githubusercontent.com serves as the link target's
    name rather than its content, so the manifest is the way to find the file.
    """
    releases = yaml.safe_load(manifest_text)
    for release in releases:
        if version is not None and str(release["release"]) != version:
            continue
        for entry in release["versions"]:
            if str(entry["format-version"]).split(".")[0] == str(FORMAT):
                return str(entry["path"])
        raise SystemExit(f"ATLAS {release['release']} has no format {FORMAT} file")
    raise SystemExit(f"ATLAS release {version} not found in the manifest")


def extract(atlas: dict[str, Any], source: str) -> dict[str, Any]:
    if str(atlas.get("format-version", "")).split(".")[0] != str(FORMAT):
        raise SystemExit(f"expected ATLAS data format {FORMAT}, got {atlas.get('format-version')}")
    relationships = atlas.get("relationships", {})

    # Tactics in matrix order (Reconnaissance ... Impact), for sorting reports.
    matrix_id = atlas["matrix"]["id"]
    order = sorted(
        relationships.get(matrix_id, {}).get("sequences", []), key=lambda r: r["position"]
    )
    shortnames = {tactic_id: shortname(t["name"]) for tactic_id, t in atlas["tactics"].items()}
    tactics = [
        {
            "id": entry["target"],
            "shortname": shortnames[entry["target"]],
            "name": atlas["tactics"][entry["target"]]["name"],
            "url": f"{SITE}/tactics/{entry['target']}",
            **with_summary(atlas["tactics"][entry["target"]]),
        }
        for entry in order
    ]

    # Who mitigates and who employs each technique, from the other end of the relationships.
    mitigated: dict[str, dict[str, str]] = {}
    employed: dict[str, list[str]] = {}
    together: dict[str, Counter[str]] = {}
    for origin, links in relationships.items():
        for link in links.get("mitigates", []):
            how = plain(str(link.get("description") or ""))
            mitigated.setdefault(link["target"], {})[origin] = how
        used = list(dict.fromkeys(link["target"] for link in links.get("employs", [])))
        for technique_id in used:
            employed.setdefault(technique_id, []).append(origin)
            together.setdefault(technique_id, Counter()).update(
                other for other in used if other != technique_id
            )
    parents = {
        technique_id: links["specializes"][0]["target"]
        for technique_id, links in relationships.items()
        if links.get("specializes")
    }
    children: dict[str, list[str]] = {}
    for child, parent in sorted(parents.items()):
        children.setdefault(parent, []).append(child)
    studies = atlas.get("case-studies", {})

    techniques = {}
    for technique_id, technique in atlas["techniques"].items():
        links = relationships.get(technique_id, {})
        parent = parents.get(technique_id)
        related = {parent: "parent technique"} if parent else {}
        related |= {child: "sub-technique" for child in children.get(technique_id, [])}
        related |= {
            sibling: "same parent technique"
            for sibling in children.get(parent or "", [])
            if sibling != technique_id
        }
        ranked = sorted(together.get(technique_id, {}).items(), key=lambda kv: (-kv[1], kv[0]))
        for other, count in [kv for kv in ranked if kv[0] not in related][:RELATED_BY_CASE]:
            related[other] = f"employed together in {count} case stud{'y' if count == 1 else 'ies'}"
        techniques[technique_id] = {
            "name": technique["name"],
            "tactics": [shortnames[link["target"]] for link in links.get("achieves", [])],
            "url": f"{SITE}/techniques/{technique_id}",
            **with_summary(technique),
            "description": plain(str(technique.get("description") or "")),
            "maturity": str(technique.get("maturity") or ""),
            "mitigations": dict(sorted(mitigated.get(technique_id, {}).items())),
            "related": related,
            # Newest first: the report shows the first ones.
            "case_studies": sorted(
                employed.get(technique_id, []),
                key=lambda cs: (str(studies[cs].get("start-date") or ""), cs),
                reverse=True,
            ),
        }

    collection = atlas["collection"]
    modified = str(collection["modified-date"])
    return {
        "atlas_version": str(collection["version"]),
        "modified": modified,
        "source": source,
        "copyright": COPYRIGHT.format(year=modified[:4]),
        "tactics": tactics,
        "techniques": dict(sorted(techniques.items())),
        "mitigations": {
            mitigation_id: {
                "name": mitigation["name"],
                "url": f"{SITE}/mitigations/{mitigation_id}",
                **with_summary(mitigation),
            }
            for mitigation_id, mitigation in sorted(atlas.get("mitigations", {}).items())
        },
        "case_studies": {
            study_id: {
                "name": study["name"],
                "url": f"{SITE}/studies/{study_id}",
                "type": str(study.get("type") or ""),
                "date": str(study.get("start-date") or "")[:4],
                **with_summary(study),
            }
            for study_id, study in sorted(studies.items())
        },
    }


def with_summary(obj: dict[str, Any]) -> dict[str, str]:
    """``{"summary": ...}`` for an object with a description, ``{}`` otherwise."""
    text = summarize(str(obj.get("description") or ""))
    return {"summary": text} if text else {}


def plain(description: str) -> str:
    """A description as plain text, one line per paragraph.

    ATLAS descriptions are Markdown: links keep their text, HTML tags and the
    ``[[reference]]`` markers are dropped.
    """
    text = re.sub(r"\s*\[\[[^\]]+\]\]", "", description.strip())
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"<[^>]+>", "", text)
    paragraphs = (" ".join(paragraph.split()) for paragraph in text.split("\n\n"))
    return "\n".join(paragraph for paragraph in paragraphs if paragraph)


def summarize(description: str) -> str:
    """The first sentences of a description, as plain text, up to SUMMARY_LENGTH characters."""
    paragraph = plain(description).split("\n")[0]
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


def shortname(name: str) -> str:
    """A tactic's tag name, written like ATT&CK's: "AI Model Access" -> "ai-model-access"."""
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


if __name__ == "__main__":
    raise SystemExit(main())
