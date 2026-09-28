"""Map Sigma ``attack.*`` tags to MITRE ATT&CK techniques and tactics.

Sigma rules carry tags such as ``attack.t1003.001`` (a technique) and
``attack.credential-access`` (a tactic). This module resolves them against a
local extract of Enterprise ATT&CK (see ``tools/build_attack_data.py``), so the
report can show names and links without any network access.

Tactics are taken from the techniques, as ATT&CK defines them in the bundled
release; tactic tags are only a fallback for rules without a technique. Rule
tags age: ATT&CK revokes and renumbers techniques, and v19 renamed the
"defense-evasion" tactic to "stealth" while moving part of its techniques to
the new "defense-impairment" tactic. Revoked ids are followed to their
replacement and the old tactic name is still understood.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any

TECHNIQUE_TAG = re.compile(r"^t\d{4}(?:\.\d{3})?$")
# Groups (G0007), software (S0002), data components (DC0001)...: valid tags
# that describe the rule but are not techniques or tactics.
OTHER_ATTACK_TAG = re.compile(r"^(?:g|s|c|m|dc|ds|da)\d{4}$")
# Tactic shortnames that changed, mapped to the current tactic id.
LEGACY_TACTICS = {"defense-evasion": "TA0005"}  # renamed "stealth" in ATT&CK v19


@dataclass(frozen=True)
class Tactic:
    id: str
    shortname: str
    name: str
    url: str


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...]  # tactic shortnames
    url: str
    parent_name: str | None = None

    @property
    def display_name(self) -> str:
        """``"OS Credential Dumping: LSASS Memory"`` for a sub-technique, as ATT&CK writes it."""
        return f"{self.parent_name}: {self.name}" if self.parent_name else self.name


@dataclass(frozen=True)
class AttackMapping:
    """What a rule's tags resolve to."""

    techniques: tuple[Technique, ...] = ()
    tactics: tuple[Tactic, ...] = ()
    unknown: tuple[str, ...] = ()  # attack.* tags that match nothing in ATT&CK
    revoked: tuple[tuple[str, str], ...] = ()  # (old id, replacement id)


class AttackData:
    """A loaded ATT&CK extract."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.version: str = data["attack_version"]
        self.copyright: str = data["copyright"]
        self.tactics: tuple[Tactic, ...] = tuple(Tactic(**tactic) for tactic in data["tactics"])
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
                parent_name=raw.get(technique_id.split(".")[0], {}).get("name")
                if "." in technique_id
                else None,
            )
            for technique_id, entry in raw.items()
        }
        self._revoked: dict[str, str] = data["revoked"]

    @classmethod
    def load(cls, path: str | Path | None = None) -> AttackData:
        """Load an extract; by default the one shipped with Vigie."""
        if path is None:
            source = resources.files("vigie.attack") / "data" / "enterprise_attack.json"
            return cls(json.loads(source.read_text(encoding="utf-8")))
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    def technique(self, technique_id: str) -> Technique | None:
        """Look a technique up by id (case-insensitive), following revocations."""
        key = technique_id.upper()
        key = self._revoked.get(key, key)
        return self._techniques.get(key)

    def tactic(self, name: str) -> Tactic | None:
        """Look a tactic up by shortname (``credential-access`` or ``credential_access``)."""
        shortname = name.lower().replace("_", "-")
        if shortname in LEGACY_TACTICS:
            return self._tactics_by_id.get(LEGACY_TACTICS[shortname])
        return self._tactics_by_name.get(shortname)

    def map_tags(self, tags: Iterable[str]) -> AttackMapping:
        techniques: dict[str, Technique] = {}
        tag_tactics: dict[str, Tactic] = {}
        unknown: list[str] = []
        revoked: list[tuple[str, str]] = []

        for tag in tags:
            lowered = tag.lower()
            if not lowered.startswith("attack."):
                continue
            value = lowered.removeprefix("attack.")
            if TECHNIQUE_TAG.match(value):
                technique = self.technique(value)
                if technique is None:
                    unknown.append(tag)
                    continue
                if technique.id != value.upper():
                    revoked.append((value.upper(), technique.id))
                techniques.setdefault(technique.id, technique)
            elif OTHER_ATTACK_TAG.match(value):
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
            revoked=tuple(revoked),
        )


@lru_cache(maxsize=1)
def default_attack_data() -> AttackData:
    """The ATT&CK extract shipped with Vigie, loaded once."""
    return AttackData.load()
