"""The ATLAS context of a technique: what an analyst reads next to an alert.

Built from the bundled ATLAS extract only, without any network access: the
description of the technique, its tactics and maturity, the mitigations with
what each one does against it, the related techniques and a few case studies
that employ it. A sub-technique without mitigations or case studies of its own
shows those of its parent technique, and says so.
"""

from __future__ import annotations

from dataclasses import dataclass

from vigie.atlas.mapping import AtlasData
from vigie.attack.mapping import Tactic, Technique

CASE_STUDY_LIMIT = 3


@dataclass(frozen=True)
class Reference:
    """Another ATLAS object, and what links it to the technique."""

    id: str
    name: str
    url: str
    note: str = ""


@dataclass(frozen=True)
class TechniqueContext:
    technique: Technique
    description: str
    tactics: tuple[Tactic, ...]
    maturity: str  # "Feasible", "Demonstrated" or "Realized"
    mitigations: tuple[Reference, ...]
    related: tuple[Reference, ...]
    case_studies: tuple[Reference, ...]  # at most CASE_STUDY_LIMIT, newest first
    case_study_count: int
    inherited_from: str = ""  # parent id, when mitigations or case studies come from it


def lookup(atlas: AtlasData, object_id: str) -> Reference | None:
    """Any object of the bundled extract by id: technique, tactic, mitigation or case study."""
    key = object_id.upper()
    technique = atlas.technique(key)
    if technique is not None:
        return Reference(key, technique.display_name, technique.url)
    tactic = atlas.tactic(key) if key.startswith("AML.TA") else None
    if tactic is not None:
        return Reference(key, tactic.name, tactic.url)
    entry = atlas.mitigations.get(key) or atlas.case_studies.get(key)
    return Reference(key, entry["name"], entry["url"]) if entry else None


def technique_context(atlas: AtlasData, technique_id: str) -> TechniqueContext | None:
    technique = atlas.technique(technique_id)
    if technique is None:
        return None
    entry = atlas.entries[technique.id]
    parent_id = technique.id.rsplit(".", 1)[0] if technique.parent_name else ""
    parent = atlas.entries.get(parent_id, {})
    mitigations = entry.get("mitigations") or {}
    studies = entry.get("case_studies") or []
    inherited = bool(parent) and (
        (not mitigations and bool(parent.get("mitigations")))
        or (not studies and bool(parent.get("case_studies")))
    )
    mitigations = mitigations or parent.get("mitigations") or {}
    studies = studies or parent.get("case_studies") or []
    return TechniqueContext(
        technique=technique,
        description=entry.get("description") or atlas.summary(technique.id),
        tactics=tuple(t for t in atlas.tactics if t.shortname in technique.tactics),
        maturity=entry.get("maturity", ""),
        mitigations=tuple(
            Reference(key, atlas.mitigations[key]["name"], atlas.mitigations[key]["url"], how)
            for key, how in mitigations.items()
            if key in atlas.mitigations
        ),
        related=tuple(
            Reference(key, other.display_name, other.url, why)
            for key, why in (entry.get("related") or {}).items()
            if (other := atlas.technique(key)) is not None
        ),
        case_studies=tuple(
            Reference(
                key,
                atlas.case_studies[key]["name"],
                atlas.case_studies[key]["url"],
                _study_note(atlas.case_studies[key]),
            )
            for key in studies[:CASE_STUDY_LIMIT]
            if key in atlas.case_studies
        ),
        case_study_count=len(studies),
        inherited_from=parent_id if inherited else "",
    )


def _study_note(study: dict[str, str]) -> str:
    label = ", ".join(part for part in (study.get("type"), study.get("date")) if part)
    summary = study.get("summary", "")
    return f"{label}. {summary}" if label and summary else label or summary


def render_text(context: TechniqueContext, atlas_version: str) -> str:
    """The context as plain text: for the terminal, and for the prompt of the agent mode."""
    t = context.technique
    lines = [
        f"{t.id} {t.display_name} (MITRE ATLAS {atlas_version})",
        t.url,
        f"Tactics: {', '.join(f'{x.name} ({x.id})' for x in context.tactics) or '-'}",
        f"Maturity: {context.maturity or '-'}",
        "",
        context.description,
    ]
    origin = (
        f" (of the parent technique {context.inherited_from})" if context.inherited_from else ""
    )
    sections = (
        (f"Mitigations{origin}", context.mitigations),
        ("Related techniques", context.related),
        (
            f"Case studies{origin} ({len(context.case_studies)} of {context.case_study_count})",
            context.case_studies,
        ),
    )
    for title, references in sections:
        if references:
            lines += ["", f"{title}:"]
            lines += [
                f"- {r.id} {r.name}{': ' + r.note if r.note else ''} [{r.url}]" for r in references
            ]
    return "\n".join(lines)
