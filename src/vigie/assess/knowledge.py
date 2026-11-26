"""The attack techniques `vigie assess` reasons about, from the bundled MITRE data.

An assessment needs, for each technique an attacker may use, the stages of an
attack it serves (its tactics), the mitigations MITRE lists against it, and how
common it is in real attacks, to rank the easiest way through. Two knowledge
bases are read, both shipped with Vigie and used offline:

* MITRE ATT&CK Enterprise, for attacks on an information system: mitigations
  come from its ``mitigates`` relationships, and how common a technique is from
  the number of known groups, campaigns, malware and tools that use it;
* MITRE ATLAS, for attacks on AI systems: mitigations come from each technique's
  entry, and how common it is from its maturity (Feasible, Demonstrated,
  Realized) and the number of case studies that employ it.

Only techniques are kept, not sub-techniques: a technique carries the
mitigations of its sub-techniques too, so a control against password spraying
(a sub-technique of Brute Force) counts against Brute Force.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from vigie.atlas import AtlasData, default_atlas_data
from vigie.attack import AttackData, default_attack_data

# ATT&CK mitigations that are not preventive controls: "Pre-compromise" says a
# technique happens outside the organization (Reconnaissance, Resource
# Development) and "Do Not Mitigate" that mitigating it would do more harm.
NOT_PREVENTIVE = frozenset({"M1055", "M1056"})
ATLAS_MATURITY_WEIGHT = {"Realized": 3.0, "Demonstrated": 2.0, "Feasible": 1.0}
SUMMARY_LIMIT = 240  # characters of a technique's summary kept for the page


@dataclass(frozen=True)
class Stage:
    """A tactic, as a stage of an attack."""

    id: str
    shortname: str
    name: str
    url: str
    summary: str


@dataclass(frozen=True)
class Mitigation:
    id: str
    name: str
    url: str
    summary: str
    framework: str  # "attack" or "atlas"


@dataclass(frozen=True)
class AttackTechnique:
    id: str
    name: str
    url: str
    summary: str
    stages: tuple[str, ...]  # tactic shortnames, in the framework's order
    mitigations: tuple[str, ...]  # preventive mitigation ids, own and sub-techniques'
    weight: float  # how common the technique is, for ranking (1 and above)
    prevalence: str  # what the weight is based on, in words
    preventable: bool  # False when MITRE lists no preventive mitigation


@dataclass(frozen=True)
class Framework:
    key: str  # "attack" or "atlas"
    label: str  # "MITRE ATT&CK"
    scope: str  # "Enterprise", "AI systems"
    version: str
    copyright: str
    stages: tuple[Stage, ...]
    techniques: tuple[AttackTechnique, ...]

    def stage(self, shortname: str) -> Stage | None:
        return next((stage for stage in self.stages if stage.shortname == shortname), None)


@dataclass(frozen=True)
class KnowledgeBase:
    frameworks: tuple[Framework, ...]
    mitigations: dict[str, Mitigation]

    def framework(self, key: str) -> Framework:
        return next(framework for framework in self.frameworks if framework.key == key)

    def technique(self, technique_id: str) -> AttackTechnique | None:
        """A technique by id; a sub-technique id gives its parent technique."""
        wanted = parent_id(technique_id.upper())
        for framework in self.frameworks:
            for technique in framework.techniques:
                if technique.id == wanted:
                    return technique
        return None


def parent_id(technique_id: str) -> str:
    """``T1059`` for ``T1059.001``, ``AML.T0051`` for ``AML.T0051.001``."""
    technique_id = technique_id.upper()
    if technique_id.startswith("AML."):
        parts = technique_id.split(".")
        return ".".join(parts[:2])
    return technique_id.split(".")[0]


def build(attack: AttackData, atlas: AtlasData) -> KnowledgeBase:
    mitigations = {
        mitigation_id: Mitigation(
            id=mitigation_id,
            name=entry["name"],
            url=entry.get("url", ""),
            summary=entry.get("summary", ""),
            framework="attack",
        )
        for mitigation_id, entry in attack.mitigations.items()
    } | {
        mitigation_id: Mitigation(
            id=mitigation_id,
            name=entry["name"],
            url=entry.get("url", ""),
            summary=entry.get("summary", ""),
            framework="atlas",
        )
        for mitigation_id, entry in atlas.mitigations.items()
    }
    return KnowledgeBase(
        frameworks=(_attack_framework(attack), _atlas_framework(atlas)),
        mitigations=mitigations,
    )


@lru_cache(maxsize=1)
def default_knowledge() -> KnowledgeBase:
    """The knowledge base built from the MITRE data shipped with Vigie, built once."""
    return build(default_attack_data(), default_atlas_data())


def _attack_framework(attack: AttackData) -> Framework:
    entries = attack.entries
    family: dict[str, set[str]] = {}
    for technique_id, entry in entries.items():
        family.setdefault(parent_id(technique_id), set()).update(entry.get("mitigations", ()))
    techniques = []
    for technique_id, entry in entries.items():
        if "." in technique_id:
            continue
        listed = family.get(technique_id, set())
        preventive = tuple(sorted(listed - NOT_PREVENTIVE))
        users = int(entry.get("used_by", 0))
        techniques.append(
            AttackTechnique(
                id=technique_id,
                name=entry["name"],
                url=entry["url"],
                summary=_short(entry.get("summary", "")),
                stages=_ordered(entry["tactics"], attack.tactics),
                mitigations=preventive,
                weight=round(1 + math.log2(1 + users), 3),
                prevalence=(
                    f"used by {users} known group{'s' if users != 1 else ''}, campaign"
                    f"{'s' if users != 1 else ''} or piece{'s' if users != 1 else ''} of software"
                    if users
                    else "no known use recorded by MITRE"
                ),
                preventable=bool(preventive),
            )
        )
    return Framework(
        key="attack",
        label="MITRE ATT&CK",
        scope="Enterprise",
        version=attack.version,
        copyright=attack.copyright,
        stages=_stages(attack.tactics, attack.summary),
        techniques=tuple(sorted(techniques, key=lambda t: t.id)),
    )


def _atlas_framework(atlas: AtlasData) -> Framework:
    entries = atlas.entries
    family: dict[str, set[str]] = {}
    for technique_id, entry in entries.items():
        family.setdefault(parent_id(technique_id), set()).update(entry.get("mitigations", {}))
    techniques = []
    for technique_id, entry in entries.items():
        if technique_id.count(".") > 1:
            continue
        maturity = entry.get("maturity", "")
        cases = len(entry.get("case_studies", ()))
        preventive = tuple(sorted(family.get(technique_id, set())))
        weight = ATLAS_MATURITY_WEIGHT.get(maturity, 1.0) + 0.5 * min(cases, 4)
        parts = [maturity.lower()] if maturity else []
        if cases:
            parts.append(f"employed in {cases} case stud{'ies' if cases != 1 else 'y'}")
        techniques.append(
            AttackTechnique(
                id=technique_id,
                name=entry["name"],
                url=entry["url"],
                summary=_short(entry.get("summary", "")),
                stages=_ordered(entry["tactics"], atlas.tactics),
                mitigations=preventive,
                weight=round(weight, 3),
                prevalence=", ".join(parts).capitalize() if parts else "No case study yet",
                preventable=bool(preventive),
            )
        )
    return Framework(
        key="atlas",
        label="MITRE ATLAS",
        scope="AI systems",
        version=atlas.version,
        copyright=atlas.copyright,
        stages=_stages(atlas.tactics, atlas.summary),
        techniques=tuple(sorted(techniques, key=lambda t: t.id)),
    )


def _stages(tactics: Any, summary: Any) -> tuple[Stage, ...]:
    return tuple(
        Stage(
            id=tactic.id,
            shortname=tactic.shortname,
            name=tactic.name,
            url=tactic.url,
            summary=summary(tactic.id),
        )
        for tactic in tactics
    )


def _ordered(shortnames: list[str], tactics: Any) -> tuple[str, ...]:
    rank = {tactic.shortname: index for index, tactic in enumerate(tactics)}
    return tuple(sorted((name for name in shortnames if name in rank), key=rank.__getitem__))


def _short(text: str) -> str:
    # Drop a last sentence that only introduces a list ("..., including:").
    sentences = re.split(r"(?<=[.!?])\s+", text)
    while len(sentences) > 1 and sentences[-1].rstrip().endswith(":"):
        sentences.pop()
    text = " ".join(sentences)
    if len(text) <= SUMMARY_LIMIT:
        return text
    return text[: SUMMARY_LIMIT - 1].rsplit(" ", 1)[0] + "…"
