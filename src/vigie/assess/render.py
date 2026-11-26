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
from vigie.assess.knowledge import KnowledgeBase, default_knowledge
from vigie.assess.questionnaire import COLUMNS, Questionnaire, level_names

OPEN_STATUSES = ("facilitated", "unpreventable")


def payload(
    questionnaire: Questionnaire,
    knowledge: KnowledgeBase | None = None,
    observed: dict[str, int] | None = None,
    generated_at: str = "",
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
        "controls": [
            {
                "id": control.id,
                "title": control.title,
                "domain": control.domain,
                "description": control.description,
                "mitigations": list(control.mitigations),
                "techniques": list(control.techniques),
                "maturity": control.maturity,
                "notes": control.notes,
            }
            for control in questionnaire.controls
        ],
        "observed": dict(sorted((observed or {}).items())),
        "warnings": list(questionnaire.warnings),
    }


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
