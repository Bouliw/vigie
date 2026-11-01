"""Map Sigma ``atlas.*`` tags to MITRE ATLAS techniques and tactics.

MITRE ATLAS (Adversarial Threat Landscape for AI Systems) is the ATT&CK-style
knowledge base of attacks on AI systems: prompt injection, jailbreaks, data
leaking through a model, abuse of an AI agent's tools... Sigma defines no tag
namespace for it, so Vigie's rules use their own, written like ``attack.*``:

* ``atlas.aml.t0051.001``: a technique, by its ATLAS id (``AML.T0051.001``);
* ``atlas.execution``: a tactic, by its name in lowercase with dashes, or by
  its id (``atlas.aml.ta0005``).

ATLAS tactics share most of their names with ATT&CK tactics (Execution,
Credential Access...) but are separate objects with their own ids, so the two
namespaces are resolved separately and the report shows them side by side.
As for ATT&CK, tactics come from the techniques, as the bundled release
defines them; tactic tags are only a fallback for rules without a technique.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any

from vigie.attack.mapping import AttackMapping, Tactic, Technique

TAG_PREFIX = "atlas."
TECHNIQUE_TAG = re.compile(r"^aml\.t\d{4}(?:\.\d{3})?$")
TACTIC_ID_TAG = re.compile(r"^aml\.ta\d{4}$")
# Mitigations (AML.M0015) and case studies (AML.CS0000): valid tags that
# describe the rule but are not techniques or tactics.
OTHER_ATLAS_TAG = re.compile(r"^aml\.(?:m|cs)\d{4}$")


class AtlasData:
    """A loaded ATLAS extract."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.version: str = data["atlas_version"]
        self.copyright: str = data["copyright"]
        self.tactics: tuple[Tactic, ...] = tuple(
            Tactic(**{key: value for key, value in tactic.items() if key != "summary"})
            for tactic in data["tactics"]
        )
        self._tactic_rank = {tactic.shortname: rank for rank, tactic in enumerate(self.tactics)}
        self._tactics_by_id = {tactic.id: tactic for tactic in self.tactics}
        self._tactics_by_name = {tactic.shortname: tactic for tactic in self.tactics}
        raw = data["techniques"]
        self._techniques = {
            technique_id: Technique(
                id=technique_id,
                name=entry["name"],
                tactics=tuple(entry["tactics"]),
                url=entry["url"],
                parent_name=raw.get(technique_id.rsplit(".", 1)[0], {}).get("name")
                if technique_id.count(".") == 2
                else None,
            )
            for technique_id, entry in raw.items()
        }
        # One or two sentences of each description, for the HTML report.
        self._summaries: dict[str, str] = {
            item["id"]: item["summary"] for item in data["tactics"] if item.get("summary")
        } | {key: entry["summary"] for key, entry in raw.items() if entry.get("summary")}

    @classmethod
    def load(cls, path: str | Path | None = None) -> AtlasData:
        """Load an extract; by default the one shipped with Vigie."""
        if path is None:
            source = resources.files("vigie.atlas") / "data" / "atlas.json"
            return cls(json.loads(source.read_text(encoding="utf-8")))
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    def technique(self, technique_id: str) -> Technique | None:
        """Look a technique up by id, case-insensitive (``AML.T0051.001``)."""
        return self._techniques.get(technique_id.upper())

    def summary(self, object_id: str) -> str:
        """The first sentences of a technique's or tactic's description, or ``""``."""
        return self._summaries.get(object_id.upper(), "")

    def tactic(self, name: str) -> Tactic | None:
        """Look a tactic up by tag name (``credential-access``) or id (``AML.TA0013``)."""
        if TACTIC_ID_TAG.match(name.lower()):
            return self._tactics_by_id.get(name.upper())
        return self._tactics_by_name.get(name.lower().replace("_", "-"))

    def map_tags(self, tags: Iterable[str]) -> AttackMapping:
        """Resolve the ``atlas.*`` tags of a rule; other tags are ignored."""
        techniques: dict[str, Technique] = {}
        tag_tactics: dict[str, Tactic] = {}
        unknown: list[str] = []

        for tag in tags:
            lowered = tag.lower()
            if not lowered.startswith(TAG_PREFIX):
                continue
            value = lowered.removeprefix(TAG_PREFIX)
            if TECHNIQUE_TAG.match(value):
                technique = self.technique(value)
                if technique is None:
                    unknown.append(tag)
                    continue
                techniques.setdefault(technique.id, technique)
            elif OTHER_ATLAS_TAG.match(value):
                continue
            elif (tactic := self.tactic(value)) is not None:
                tag_tactics.setdefault(tactic.shortname, tactic)
            else:
                unknown.append(tag)

        shortnames = {name for technique in techniques.values() for name in technique.tactics}
        tactics = [self._tactics_by_name[name] for name in shortnames if name in self._tactic_rank]
        if not tactics:
            tactics = list(tag_tactics.values())
        tactics.sort(key=lambda tactic: self._tactic_rank[tactic.shortname])
        return AttackMapping(
            techniques=tuple(sorted(techniques.values(), key=lambda t: t.id)),
            tactics=tuple(tactics),
            unknown=tuple(unknown),
        )


@lru_cache(maxsize=1)
def default_atlas_data() -> AtlasData:
    """The ATLAS extract shipped with Vigie, loaded once."""
    return AtlasData.load()
