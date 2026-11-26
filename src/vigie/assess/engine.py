"""From maturity levels to the attack techniques they leave open, and the easiest way through.

The reasoning, kept simple enough to be explained to the people assessed:

1. A control implements MITRE mitigations (or counters techniques directly). A
   mitigation is as strong as the most mature control implementing it.
2. A technique is as hard as the strongest mitigation MITRE lists against it:
   with maturity ``m`` on a scale of ``s``, the ratio ``m / s`` is below 0.4 =
   *facilitated*, below 0.8 = *partly hindered*, and from 0.8 = *hindered*. A
   technique none of whose mitigations was assessed is *not assessed*, and one
   MITRE lists no preventive mitigation for (most of Reconnaissance, many
   Discovery techniques) *cannot be prevented by controls*.
3. An attacker goes through the stages of an attack (the tactics, from
   Reconnaissance to Impact) and at each one picks the easiest technique. The
   *easiest path* shows that technique stage by stage: a facilitated one first,
   then one no control can prevent, then the least hindered. It is *blocked* at
   the first stage where even the easiest technique is hindered.
4. The *exposure index* (0 to 100) is the mean of ``1 - m / s`` over the
   assessed techniques that controls can prevent, weighted by how common each
   technique is in real attacks.
5. The *priorities* are the assessed controls whose raise to the hindered level
   would stop the most techniques from being facilitated, each technique counted
   by how common it is, double on the easiest path, triple when seen in the
   logs, and half when it only serves the stages that happen before any contact
   with the organization (Reconnaissance, Resource Development, AI Attack
   Adaptation).

``facilitated`` is a heuristic built on MITRE's mapping of mitigations to
techniques, not a probability: it says where a control gap leaves a known
technique without its main counter-measure. The same rules run in the browser,
in the interactive page (``templates/_assess.js.j2``); the tests check both
give the same results.
"""

from __future__ import annotations

import math
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from vigie import __version__
from vigie.assess.knowledge import (
    AttackTechnique,
    Framework,
    KnowledgeBase,
    Stage,
    default_knowledge,
    parent_id,
)
from vigie.assess.questionnaire import Control, Questionnaire
from vigie.timeutils import UTC

FACILITATED_BELOW = 0.4
HINDERED_FROM = 0.8
STATUSES = ("facilitated", "unpreventable", "partial", "hindered", "unassessed")
STATUS_LABELS = {
    "facilitated": "Facilitated",
    "unpreventable": "No preventive control",
    "partial": "Partly hindered",
    "hindered": "Hindered",
    "unassessed": "Not assessed",
}
PRIORITY_LIMIT = 12
# Stages played out away from the organization: their techniques count half in
# the priorities, which aim at what an organization's controls stop first.
PRE_COMPROMISE = frozenset({"reconnaissance", "resource-development", "ai-attack-adaptation"})


@dataclass(frozen=True)
class TechniqueResult:
    technique: AttackTechnique
    framework: str
    status: str
    level: float | None  # maturity of the strongest mitigation, None if not assessed
    exposure: float | None  # 1 - level / scale; 1 when unpreventable; None if not assessed
    controls: tuple[str, ...]  # ids of the controls that map to the technique
    uncovered: tuple[str, ...]  # its mitigations no control of the questionnaire implements
    observed: int = 0  # alerts on the technique (or a sub-technique) in the logs


@dataclass(frozen=True)
class StageResult:
    stage: Stage
    techniques: tuple[TechniqueResult, ...]  # easiest first
    counts: dict[str, int]
    facilitated_share: float | None  # weighted share of the assessed preventable ones
    step: TechniqueResult | None  # what the easiest path takes at this stage
    status: str  # the step's status
    observed: int


@dataclass(frozen=True)
class FrameworkResult:
    framework: Framework
    stages: tuple[StageResult, ...]
    blocked_at: str | None  # shortname of the first stage the easiest path cannot pass
    exposure_index: int | None
    counts: dict[str, int]
    assessed: int  # techniques assessed (any status but unassessed and unpreventable)

    @property
    def path(self) -> list[StageResult]:
        """The stages of the easiest path, up to the one it is blocked at."""
        steps = []
        for stage in self.stages:
            if stage.step is None:
                continue
            steps.append(stage)
            if stage.stage.shortname == self.blocked_at:
                break
        return steps


@dataclass(frozen=True)
class Priority:
    control: Control
    target: float
    relieved: tuple[str, ...]  # techniques no longer facilitated at the target level
    on_path: int
    observed: int
    gain: float


@dataclass
class Assessment:
    questionnaire: Questionnaire
    frameworks: tuple[FrameworkResult, ...]
    priorities: list[Priority]
    observed: dict[str, int]  # alerts per technique id (techniques, not sub-techniques)
    unknown_ids: list[str] = field(default_factory=list)
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    vigie_version: str = __version__

    @property
    def scale(self) -> int:
        return self.questionnaire.scale

    def framework(self, key: str) -> FrameworkResult:
        return next(result for result in self.frameworks if result.framework.key == key)

    @property
    def observed_open(self) -> list[TechniqueResult]:
        """Techniques seen in the logs that the maturity leaves facilitated or unpreventable."""
        found = [
            technique
            for result in self.frameworks
            for stage in result.stages
            for technique in stage.techniques
            if technique.observed and technique.status in ("facilitated", "unpreventable")
        ]
        unique = {technique.technique.id: technique for technique in found}
        return sorted(unique.values(), key=lambda t: (-t.observed, t.technique.id))


def assess(
    questionnaire: Questionnaire,
    knowledge: KnowledgeBase | None = None,
    observed: dict[str, int] | None = None,
) -> Assessment:
    """Run the assessment of ``questionnaire``; ``observed`` counts alerts per technique id."""
    knowledge = knowledge or default_knowledge()
    scale = questionnaire.scale
    seen: dict[str, int] = {}
    for technique_id, count in (observed or {}).items():
        key = parent_id(technique_id.upper())
        seen[key] = seen.get(key, 0) + count

    known_techniques = {t.id for f in knowledge.frameworks for t in f.techniques}
    unknown: list[str] = []
    for control in questionnaire.controls:
        for mitigation_id in control.mitigations:
            if mitigation_id not in knowledge.mitigations and mitigation_id not in unknown:
                unknown.append(mitigation_id)
        for technique_id in control.techniques:
            if parent_id(technique_id) not in known_techniques and technique_id not in unknown:
                unknown.append(technique_id)

    levels = _levels(questionnaire.controls)
    results = tuple(
        _framework(framework, questionnaire.controls, levels, scale, seen)
        for framework in knowledge.frameworks
    )
    priorities = _priorities(questionnaire, results, scale)
    return Assessment(
        questionnaire=questionnaire,
        frameworks=results,
        priorities=priorities,
        observed=seen,
        unknown_ids=unknown,
    )


def observed_techniques(alerts: Iterable[Any]) -> dict[str, int]:
    """Alerts per ATT&CK or ATLAS technique id, from the alerts of a report."""
    counts: dict[str, int] = {}
    for alert in alerts:
        for mapping in (alert.attack, alert.atlas):
            for technique in mapping.techniques:
                counts[technique.id] = counts.get(technique.id, 0) + 1
    return counts


def status_of(level: float | None, scale: int) -> str:
    if level is None:
        return "unassessed"
    ratio = level / scale
    if ratio < FACILITATED_BELOW:
        return "facilitated"
    if ratio < HINDERED_FROM:
        return "partial"
    return "hindered"


def target_level(scale: int) -> float:
    """The lowest level that counts as hindered: 4 on a 0-5 scale."""
    return float(math.ceil(HINDERED_FROM * scale - 1e-9))


def _levels(controls: list[Control]) -> tuple[dict[str, float], dict[str, float]]:
    """Best maturity per mitigation id, and per technique id mapped directly."""
    by_mitigation: dict[str, float] = {}
    by_technique: dict[str, float] = {}
    for control in controls:
        if control.maturity is None:
            continue
        for mitigation_id in control.mitigations:
            by_mitigation[mitigation_id] = max(
                by_mitigation.get(mitigation_id, -1), control.maturity
            )
        for technique_id in control.techniques:
            key = parent_id(technique_id)
            by_technique[key] = max(by_technique.get(key, -1), control.maturity)
    return by_mitigation, by_technique


def _technique_level(
    technique: AttackTechnique, levels: tuple[dict[str, float], dict[str, float]]
) -> float | None:
    by_mitigation, by_technique = levels
    found = [by_mitigation[m] for m in technique.mitigations if m in by_mitigation]
    if technique.id in by_technique:
        found.append(by_technique[technique.id])
    return max(found) if found else None


def _evaluate(
    technique: AttackTechnique,
    framework: str,
    controls: list[Control],
    levels: tuple[dict[str, float], dict[str, float]],
    scale: int,
    seen: dict[str, int],
) -> TechniqueResult:
    mapped = [
        control
        for control in controls
        if any(m in technique.mitigations for m in control.mitigations)
        or any(parent_id(t) == technique.id for t in control.techniques)
    ]
    implemented = {m for control in mapped for m in control.mitigations}
    uncovered = tuple(m for m in technique.mitigations if m not in implemented)
    level = _technique_level(technique, levels)
    direct = any(parent_id(t) == technique.id for c in mapped for t in c.techniques)
    if not technique.preventable and not direct:
        status, exposure = "unpreventable", 1.0
    else:
        status = status_of(level, scale)
        exposure = None if level is None else round(1 - level / scale, 4)
    return TechniqueResult(
        technique=technique,
        framework=framework,
        status=status,
        level=level,
        exposure=exposure,
        controls=tuple(control.id for control in mapped),
        uncovered=uncovered,
        observed=seen.get(technique.id, 0),
    )


def _rank(technique: TechniqueResult) -> tuple[float, int, float, str]:
    """Sort key, easiest first: most exposed, then seen in the logs, then most common."""
    exposure = -1.0 if technique.exposure is None else technique.exposure
    return (-exposure, -technique.observed, -technique.technique.weight, technique.technique.id)


def _framework(
    framework: Framework,
    controls: list[Control],
    levels: tuple[dict[str, float], dict[str, float]],
    scale: int,
    seen: dict[str, int],
) -> FrameworkResult:
    evaluated = {
        technique.id: _evaluate(technique, framework.key, controls, levels, scale, seen)
        for technique in framework.techniques
    }
    stages = []
    blocked_at: str | None = None
    for stage in framework.stages:
        members = sorted(
            (r for r in evaluated.values() if stage.shortname in r.technique.stages), key=_rank
        )
        counts = {status: 0 for status in STATUSES}
        for member in members:
            counts[member.status] += 1
        step = _step(members)
        status = step.status if step else "unassessed"
        if status == "hindered" and blocked_at is None:
            blocked_at = stage.shortname
        stages.append(
            StageResult(
                stage=stage,
                techniques=tuple(members),
                counts=counts,
                facilitated_share=_share(members),
                step=step,
                status=status,
                observed=sum(member.observed for member in members),
            )
        )
    counts = {status: 0 for status in STATUSES}
    for result in evaluated.values():
        counts[result.status] += 1
    preventable = [
        r for r in evaluated.values() if r.status in ("facilitated", "partial", "hindered")
    ]
    weight = sum(r.technique.weight for r in preventable)
    # floor(x + 0.5), not round(): the page rounds halves up too.
    index = (
        math.floor(
            100 * sum(r.technique.weight * (r.exposure or 0) for r in preventable) / weight + 0.5
        )
        if weight
        else None
    )
    return FrameworkResult(
        framework=framework,
        stages=tuple(stages),
        blocked_at=blocked_at,
        exposure_index=index,
        counts=counts,
        assessed=len(preventable),
    )


def _step(members: list[TechniqueResult]) -> TechniqueResult | None:
    for wanted in (("facilitated",), ("unpreventable",), ("partial", "hindered")):
        for member in members:
            if member.status in wanted:
                return member
    return members[0] if members else None


def _share(members: list[TechniqueResult]) -> float | None:
    assessed = [m for m in members if m.status in ("facilitated", "partial", "hindered")]
    total = sum(m.technique.weight for m in assessed)
    if not total:
        return None
    facilitated = sum(m.technique.weight for m in assessed if m.status == "facilitated")
    return round(facilitated / total, 4)


def _priorities(
    questionnaire: Questionnaire, results: tuple[FrameworkResult, ...], scale: int
) -> list[Priority]:
    target = target_level(scale)
    on_path = {stage.step.technique.id for result in results for stage in result.path if stage.step}
    techniques = {
        technique.technique.id: technique
        for result in results
        for stage in result.stages
        for technique in stage.techniques
    }
    priorities = []
    for control in questionnaire.controls:
        if control.maturity is None or control.maturity >= target:
            continue
        relieved = []
        gain = 0.0
        path_count = observed = 0
        for technique_id in sorted(techniques):
            technique = techniques[technique_id]
            if technique.status != "facilitated" or control.id not in technique.controls:
                continue
            if status_of(target, scale) == "facilitated":
                continue
            relieved.append(technique_id)
            factor = 1.0
            if technique_id in on_path:
                factor *= 2
                path_count += 1
            if technique.observed:
                factor *= 3
                observed += 1
            if set(technique.technique.stages) <= PRE_COMPROMISE:
                factor *= 0.5
            gain += technique.technique.weight * factor
        if relieved:
            priorities.append(
                Priority(
                    control=control,
                    target=target,
                    relieved=tuple(relieved),
                    on_path=path_count,
                    observed=observed,
                    gain=round(gain, 3),
                )
            )
    priorities.sort(key=lambda p: (-p.gain, -len(p.relieved), p.control.id))
    return priorities[:PRIORITY_LIMIT]
