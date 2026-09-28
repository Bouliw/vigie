"""Build Vigie's MITRE ATT&CK extract from the official STIX bundle.

The full Enterprise ATT&CK bundle is about 54 MB. Vigie only needs, for each
technique, its name, tactics and URL, so this script keeps just that (about
120 KB) in ``src/vigie/attack/data/enterprise_attack.json``.

Usage::

    python tools/build_attack_data.py                 # latest release
    python tools/build_attack_data.py --version 19.2  # a given release
    python tools/build_attack_data.py --input enterprise-attack-19.2.json

Only the standard library is used, so the script runs without installing Vigie.
"""

from __future__ import annotations

import argparse
import json
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
        f"{len(data['techniques'])} techniques, {len(data['revoked'])} revoked ids "
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
        }

    # Older rules still use revoked ids (e.g. T1086 -> T1059.001).
    revoked = {}
    for obj in objects:
        if obj["type"] == "relationship" and obj["relationship_type"] == "revoked-by":
            old, new = by_id.get(obj["source_ref"]), by_id.get(obj["target_ref"])
            if old and new and old["type"] == "attack-pattern" and attack_id(new) in techniques:
                revoked[attack_id(old)] = attack_id(new)

    modified = collection["modified"]
    return {
        "attack_version": collection["x_mitre_version"],
        "modified": modified,
        "source": source,
        "copyright": COPYRIGHT.format(year=modified[:4]),
        "tactics": tactics,
        "techniques": dict(sorted(techniques.items())),
        "revoked": dict(sorted(revoked.items())),
    }


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
