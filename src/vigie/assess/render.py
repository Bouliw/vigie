"""Write an assessment: the interactive HTML page, a Markdown summary, JSON results."""

from __future__ import annotations

import json
from typing import Any

from jinja2 import Environment, PackageLoader, StrictUndefined

from vigie.assess.engine import (
    FACILITATED_BELOW,
    HINDERED_FROM,
    STATUS_LABELS,
    STATUSES,
    Assessment,
    FrameworkResult,
)
from vigie.assess.knowledge import KnowledgeBase, Profile, default_knowledge
from vigie.assess.questionnaire import COLUMNS, Control, Questionnaire, level_names
from vigie.assess.suggest import raw_keywords

OPEN_STATUSES = ("facilitated", "unpreventable")


def payload(
    questionnaire: Questionnaire,
    knowledge: KnowledgeBase | None = None,
    observed: dict[str, int] | None = None,
    generated_at: str = "",
    *,
    profile: Profile | None = None,
    detection: dict[str, int] | None = None,
    detection_source: str = "",
    baseline: Questionnaire | None = None,
    suggested: dict[str, list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Everything the interactive page needs; it computes the assessment itself."""
    from vigie import __version__

    knowledge = knowledge or default_knowledge()
    return {
        "meta": {
            "vigie_version": __version__,
            "generated_at": generated_at,
            "title": questionnaire.title or "Maturity assessment",
            "source": questionnaire.source,
            "scale": questionnaire.scale,
            "levels": list(level_names(questionnaire.scale)),
            "facilitated_below": FACILITATED_BELOW,
            "hindered_from": HINDERED_FROM,
            "status_labels": STATUS_LABELS,
            "columns": {key: list(aliases) for key, aliases in COLUMNS.items()},
            "copyright": [framework.copyright for framework in knowledge.frameworks],
            "detection_source": detection_source,
        },
        "frameworks": [
            {
                "key": framework.key,
                "label": framework.label,
                "scope": framework.scope,
                "version": framework.version,
                "stages": [
                    {
                        "id": stage.id,
                        "shortname": stage.shortname,
                        "name": stage.name,
                        "url": stage.url,
                        "summary": stage.summary,
                    }
                    for stage in framework.stages
                ],
                "techniques": [
                    {
                        "id": technique.id,
                        "name": technique.name,
                        "url": technique.url,
                        "summary": technique.summary,
                        "stages": list(technique.stages),
                        "mitigations": list(technique.mitigations),
                        "weight": technique.weight,
                        "prevalence": technique.prevalence,
                        "preventable": technique.preventable,
                    }
                    for technique in framework.techniques
                ],
            }
            for framework in knowledge.frameworks
        ],
        "mitigations": {
            mitigation_id: {"name": m.name, "url": m.url, "framework": m.framework}
            for mitigation_id, m in knowledge.mitigations.items()
        },
        "controls": [_control(control, suggested) for control in questionnaire.controls],
        "observed": dict(sorted((observed or {}).items())),
        "warnings": list(questionnaire.warnings),
        "sectors": dict(knowledge.sectors),
        "groups": {
            group.id: {
                "name": group.name,
                "aliases": list(group.aliases),
                "url": group.url,
                "sectors": list(group.sectors),
                "techniques": list(group.techniques),
            }
            for group in knowledge.groups
        },
        "profile": (
            None
            if profile is None
            # A sector profile is kept as a sector, so the page can show it as one.
            else {
                "sector": profile.sector,
                "groups": [] if profile.sector else list(profile.groups),
                "label": profile.label,
            }
        ),
        "detection": None if detection is None else dict(sorted(detection.items())),
        "baseline": (
            None
            if baseline is None
            else {
                "title": baseline.title,
                "source": baseline.source,
                "controls": [_control(control) for control in baseline.controls],
            }
        ),
        "keywords": raw_keywords(),
    }


def _control(
    control: Control, suggested: dict[str, list[dict[str, Any]]] | None = None
) -> dict[str, Any]:
    data = {
        "id": control.id,
        "title": control.title,
        "domain": control.domain,
        "description": control.description,
        "mitigations": list(control.mitigations),
        "techniques": list(control.techniques),
        "maturity": control.maturity,
        "notes": control.notes,
    }
    if suggested and control.id in suggested:
        data["suggested"] = suggested[control.id]
    return data


def render_html(assessment: Assessment, knowledge: KnowledgeBase | None = None) -> str:
    env = Environment(
        loader=PackageLoader("vigie.report", "templates"),
        autoescape=True,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    data = payload(
        assessment.questionnaire,
        knowledge,
        assessment.observed,
        assessment.generated_at.strftime("%Y-%m-%d %H:%M UTC"),
        profile=assessment.profile,
        detection=assessment.detection,
        detection_source=assessment.detection_source,
        baseline=assessment.baseline.questionnaire if assessment.baseline else None,
        suggested=assessment.suggested,
    )
    template = env.get_template("assessment.html.j2")
    return template.render(meta=data["meta"], payload=data, observed=bool(assessment.observed))


def render_json(assessment: Assessment) -> str:
    return json.dumps(to_dict(assessment), indent=2, ensure_ascii=False) + "\n"


def to_dict(assessment: Assessment) -> dict[str, Any]:
    questionnaire = assessment.questionnaire
    return {
        "title": questionnaire.title,
        "source": questionnaire.source,
        "scale": questionnaire.scale,
        "generated_at": assessment.generated_at.isoformat(timespec="seconds"),
        "generated_by": f"Vigie {assessment.vigie_version}",
        "controls": {"total": len(questionnaire.controls), "answered": questionnaire.answered},
        "frameworks": [_framework_dict(result) for result in assessment.frameworks],
        "priorities": [
            {
                "control": priority.control.id,
                "title": priority.control.title,
                "current": priority.control.maturity,
                "target": priority.target,
                "relieved": list(priority.relieved),
                "on_path": priority.on_path,
                "observed": priority.observed,
            }
            for priority in assessment.priorities
        ],
        "observed": assessment.observed,
        "observed_open": [t.technique.id for t in assessment.observed_open],
        "warnings": questionnaire.warnings,
        "unknown_ids": assessment.unknown_ids,
        "profile": (
            None
            if assessment.profile is None
            else {
                "label": assessment.profile.label,
                "sector": assessment.profile.sector,
                "groups": list(assessment.profile.groups),
            }
        ),
        "detection": (
            None
            if assessment.detection is None
            else {
                "source": assessment.detection_source,
                "blind_spots": [t.technique.id for t in assessment.blind_spots],
            }
        ),
        "comparison": (
            None
            if assessment.baseline is None
            else {
                "baseline": assessment.baseline.questionnaire.title,
                "frameworks": [
                    {
                        "key": change.key,
                        "exposure_index": [change.index_before, change.index_after],
                        "counts": {
                            status: [change.counts_before[status], change.counts_after[status]]
                            for status in STATUSES
                        },
                        "blocked_at": [change.blocked_before, change.blocked_after],
                        "improved": list(change.improved),
                        "worsened": list(change.worsened),
                    }
                    for change in assessment.comparison()
                ],
                "controls": [
                    {"control": control.id, "before": before, "after": after}
                    for control, before, after in assessment.changed_controls()
                ],
            }
        ),
    }


def _framework_dict(result: FrameworkResult) -> dict[str, Any]:
    framework = result.framework
    return {
        "key": framework.key,
        "name": framework.label,
        "version": framework.version,
        "exposure_index": result.exposure_index,
        "counts": result.counts,
        "blocked_at": result.blocked_at,
        "path": [
            {
                "stage": stage.stage.name,
                "technique": stage.step.technique.id if stage.step else None,
                "name": stage.step.technique.name if stage.step else None,
                "status": stage.status,
            }
            for stage in result.path
        ],
        "techniques": {
            technique.technique.id: {
                "status": technique.status,
                "level": technique.level,
                "controls": list(technique.controls),
                "observed": technique.observed,
                "detected": technique.detected,
            }
            for stage in result.stages
            for technique in stage.techniques
        },
    }


def render_markdown(assessment: Assessment) -> str:
    q = assessment.questionnaire
    lines = [f"# {q.title or 'Maturity assessment'}", ""]
    lines.append(
        f"{q.answered} of {len(q.controls)} controls answered, on a 0-{q.scale} scale. "
        f"Made with Vigie {assessment.vigie_version} on "
        f"{assessment.generated_at.strftime('%Y-%m-%d %H:%M UTC')}."
    )
    lines.append("")
    if assessment.profile:
        profile = assessment.profile
        count = len(profile.groups)
        lines.append(
            f"Threat profile: the MITRE ATT&CK techniques of the {profile.label}"
            if profile.sector
            else f"Threat profile: the MITRE ATT&CK techniques of {profile.label}"
        )
        lines[-1] += f" ({count} group{'s' if count != 1 else ''})."
        lines.append("")
    lines.extend(_comparison_lines(assessment))
    for result in assessment.frameworks:
        framework = result.framework
        lines.append(f"## {framework.label} {framework.version} ({framework.scope})")
        lines.append("")
        index = "not assessed" if result.exposure_index is None else f"{result.exposure_index}/100"
        counts = ", ".join(f"{STATUS_LABELS[s]}: {result.counts[s]}" for s in STATUSES)
        lines.append(f"Exposure index: {index}. {counts}.")
        lines.append("")
        if result.blocked_at:
            stage = framework.stage(result.blocked_at)
            lines.append(
                f"The easiest path is blocked at {stage.name if stage else result.blocked_at}."
            )
        else:
            lines.append("Nothing blocks the easiest path.")
        lines.append("")
        lines.append("| Stage | Easiest technique | Status |")
        lines.append("|---|---|---|")
        for stage in result.path:
            step = stage.step
            technique = f"{step.technique.id} {step.technique.name}" if step else "-"
            lines.append(f"| {stage.stage.name} | {technique} | {STATUS_LABELS[stage.status]} |")
        lines.append("")
    if assessment.priorities:
        lines.append("## What to raise first")
        lines.append("")
        for number, priority in enumerate(assessment.priorities, start=1):
            control = priority.control
            current = "-" if control.maturity is None else f"{control.maturity:g}"
            count = len(priority.relieved)
            text = (
                f"{number}. **{control.id} {control.title}**: {current} → {priority.target:g}, "
                f"stops {count} technique{'s' if count != 1 else ''} from being facilitated"
            )
            if priority.on_path:
                text += f", {priority.on_path} on the easiest path"
            if priority.observed:
                text += f", {priority.observed} seen in the logs"
            lines.append(text + ".")
        lines.append("")
    open_seen = assessment.observed_open
    if open_seen:
        lines.append("## Seen in the logs and left open")
        lines.append("")
        for technique in open_seen:
            lines.append(
                f"- {technique.technique.id} {technique.technique.name}: "
                f"{technique.observed} alert{'s' if technique.observed != 1 else ''}, "
                f"{STATUS_LABELS[technique.status].lower()}"
            )
        lines.append("")
    if assessment.detection is not None:
        lines.extend(_blind_spot_lines(assessment))
    if q.warnings or assessment.unknown_ids:
        lines.append("## Warnings")
        lines.append("")
        lines.extend(f"- {warning}" for warning in q.warnings)
        if assessment.unknown_ids:
            lines.append(f"- ids unknown to the MITRE data: {', '.join(assessment.unknown_ids)}")
        lines.append("")
    lines.append(
        "Facilitated means that a control gap leaves a known technique without its main "
        "counter-measure, as MITRE maps them; it is not a probability of attack."
    )
    return "\n".join(lines) + "\n"


BLIND_SPOT_LIMIT = 25


def _blind_spot_lines(assessment: Assessment) -> list[str]:
    spots = assessment.blind_spots
    source = assessment.detection_source or "the detection rules"
    lines = ["## Neither prevented nor detected", ""]
    if not spots:
        lines += [f"Every technique left open is detected by {source}.", ""]
        return lines
    lines.append(
        f"{len(spots)} technique{'s' if len(spots) != 1 else ''} left open "
        f"(facilitated, or with no preventive control) that {source} do not detect, "
        "most common first:"
    )
    lines.append("")
    ranked = sorted(spots, key=lambda t: (-t.technique.weight, t.technique.id))
    for technique in ranked[:BLIND_SPOT_LIMIT]:
        lines.append(
            f"- {technique.technique.id} {technique.technique.name}: "
            f"{STATUS_LABELS[technique.status].lower()}"
        )
    if len(ranked) > BLIND_SPOT_LIMIT:
        lines.append(f"- and {len(ranked) - BLIND_SPOT_LIMIT} more")
    lines.append("")
    return lines


def _comparison_lines(assessment: Assessment) -> list[str]:
    if assessment.baseline is None:
        return []
    title = assessment.baseline.questionnaire.title or "the previous assessment"
    lines = [f"## Since {title}", ""]
    for change in assessment.comparison():
        delta = change.index_change
        index = (
            "not comparable"
            if delta is None
            else f"{change.index_before} → {change.index_after} ({delta:+d})"
        )
        facilitated = (
            f"{change.counts_before['facilitated']} → {change.counts_after['facilitated']}"
        )
        lines.append(
            f"- {change.label}: exposure index {index}; facilitated techniques {facilitated}; "
            f"{len(change.improved)} improved, {len(change.worsened)} worsened."
        )
    changed = assessment.changed_controls()
    if changed:
        lines.append("")
        lines.append("| Control | Before | Now |")
        lines.append("|---|---|---|")
        for control, before, after in changed:
            lines.append(f"| {control.id} {control.title} | {_level(before)} | {_level(after)} |")
    lines.append("")
    return lines


def _level(value: float | None) -> str:
    return "-" if value is None else f"{value:g}"
