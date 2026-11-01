"""Render a report model as Markdown, self-contained HTML, or JSON.

Log content is attacker-controlled (user names, command lines, task XML), so
every value coming from an event is escaped: HTML with Jinja2's autoescaping,
Markdown with :func:`md`, which neutralizes table and formatting characters.

The HTML report is one file that works offline: its styles and script are
inlined, and it stays readable with JavaScript disabled (everything expanded,
no toolbar). :func:`html_view` adds what only the page needs (stable alert
anchors, technique descriptions, coverage strips) without touching the report
model, so the JSON output does not change.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, StrictUndefined

from vigie.atlas import default_atlas_data
from vigie.attack import AttackMapping, default_attack_data
from vigie.models import LEVELS, RuleMeta
from vigie.report.builder import AlertView, Report
from vigie.rules import RULES_DIR

_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]<>|#])")


def md(value: Any) -> str:
    """Escape a value for a single Markdown line or table cell."""
    text = " ".join(str(value).split())
    return _MD_SPECIAL.sub(r"\\\1", text)


def timestamp(value: datetime | None) -> str:
    """UTC time as ``2024-03-10 09:05:42Z`` (microseconds dropped for readability)."""
    if value is None:
        return "-"
    return value.strftime("%Y-%m-%d %H:%M:%SZ")


def number(value: int) -> str:
    """``1429`` as ``1,429``."""
    return f"{value:,}"


def duration(first: datetime | None, last: datetime | None) -> str:
    """How long the logs cover, roughly: ``3 days``, ``about 6 years``."""
    if first is None or last is None:
        return ""
    seconds = int((last - first).total_seconds())
    units = (("year", 365 * 86400), ("month", 30 * 86400), ("day", 86400), ("hour", 3600))
    for name, size in units:
        if seconds >= size:
            count = round(seconds / size)
            text = f"{count} {name}{'s' if count != 1 else ''}"
            return f"about {text}" if name in ("year", "month") else text
    if seconds >= 60:
        minutes = round(seconds / 60)
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    return f"{seconds} second{'s' if seconds != 1 else ''}"


def _environment(autoescape: bool) -> Environment:
    env = Environment(
        loader=PackageLoader("vigie.report", "templates"),
        # Explicit: select_autoescape() goes by file extension, and ".html.j2" is not ".html".
        autoescape=autoescape,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["md"] = md
    env.filters["ts"] = timestamp
    env.filters["num"] = number
    env.filters["duration"] = duration
    env.globals["LEVELS"] = LEVELS
    env.globals["rule_path"] = rule_path
    env.globals["safe_url"] = safe_url
    return env


def render_markdown(report: Report) -> str:
    return _environment(autoescape=False).get_template("report.md.j2").render(report=report)


def render_html(report: Report) -> str:
    template = _environment(autoescape=True).get_template("report.html.j2")
    return template.render(report=report, view=html_view(report))


# What each number at the top of the HTML report counts, for its "?" button.
LEVEL_HELP = {
    "critical": "Rules rated critical match activity that almost certainly is an incident. "
    "Review these first, now.",
    "high": "Rules rated high match activity that should raise an internal alert and be "
    "reviewed promptly.",
    "medium": "Rules rated medium match relevant activity that deserves a manual review, "
    "in the context of what else happened.",
    "low": "Rules rated low match notable activity that is rarely an incident on its own, "
    "but matters in numbers or next to other alerts.",
    "informational": "Rules rated informational add context. They are not a threat by themselves.",
}
HELP = {
    "events": "Log records Vigie read and normalized: one line of auth.log, one Windows "
    "event, one agent step. Every one of them went through every rule that applies to it.",
    "files": "Files Vigie recognized and read. Files in other formats are listed as skipped "
    "in Inputs, at the bottom of the page.",
    "sources": "Log files and streams this watch follows.",
    "rules": "Sigma detection rules run on the events. Each alert below comes from one of them.",
    "alerts": "Times a rule matched. One alert can stand for many events: a brute force is "
    "one alert for all its failed logins.",
}
LEVEL_NOTE = " The level is set by the rule's author, following the Sigma levels."


def html_view(report: Report) -> dict[str, Any]:
    """What the HTML page needs on top of the report model."""
    attack, atlas = default_attack_data(), default_atlas_data()
    frameworks = [
        ("attack", "MITRE ATT&CK", attack, report.tactics, lambda a: a.attack),
        ("atlas", "MITRE ATLAS", atlas, report.atlas_tactics, lambda a: a.atlas),
    ]
    techniques: dict[str, dict[str, Any]] = {}
    tactics: dict[str, dict[str, Any]] = {}
    strips = []
    for key, label, data, seen, pick in frameworks:
        for alert in report.alerts:
            mapping: AttackMapping = pick(alert)
            for technique in mapping.techniques:
                techniques.setdefault(
                    technique.id,
                    {
                        "id": technique.id,
                        "name": technique.display_name,
                        "summary": data.summary(technique.id),
                        "tactics": [
                            t.name for t in data.tactics if t.shortname in technique.tactics
                        ],
                        "url": technique.url,
                        "source": label,
                        "fw": key,
                    },
                )
        show = bool(seen) if key == "atlas" else bool(seen) or not report.atlas_tactics
        if not show:
            continue
        counts = {view.tactic.id: view.alert_count for view in seen}
        peak = max(counts.values(), default=0)
        cells = []
        for tactic in data.tactics:
            count = counts.get(tactic.id, 0)
            tactics[tactic.id] = {
                "id": tactic.id,
                "name": tactic.name,
                "summary": data.summary(tactic.id),
                "url": tactic.url,
                "source": label,
                "fw": key,
                "count": count,
            }
            cells.append({"tactic": tactic, "count": count, "heat": _heat(count, peak)})
        strips.append({"key": key, "label": label, "cells": cells})

    help_texts = {name: text + LEVEL_NOTE for name, text in LEVEL_HELP.items()}
    help_texts.update(HELP)
    cards = [
        {
            "anchor": anchor,
            "techniques": " ".join(
                t.id for t in (*alert.attack.techniques, *alert.atlas.techniques)
            ),
            "tactics": " ".join(t.id for t in (*alert.attack.tactics, *alert.atlas.tactics)),
            "frameworks": " ".join(
                name
                for name, mapping in (("attack", alert.attack), ("atlas", alert.atlas))
                if mapping.techniques or mapping.tactics
            ),
        }
        for anchor, alert in zip(_anchors(report.alerts), report.alerts, strict=True)
    ]
    return {
        "cards": cards,
        "strips": strips,
        "summary": lambda object_id: attack.summary(object_id) or atlas.summary(object_id),
        "data": {"techniques": techniques, "tactics": tactics, "help": help_texts},
        "both": bool(report.tactics) and bool(report.atlas_tactics),
    }


def _heat(count: int, peak: int) -> int:
    """0 (nothing) to 4 (the busiest tactic), for the coverage strip."""
    if not count or not peak:
        return 0
    return max(1, min(4, round(4 * count / peak)))


def _anchors(alerts: list[AlertView]) -> list[str]:
    """An id per alert that stays the same when ``vigie watch`` rewrites the page."""
    anchors, seen = [], set()
    for alert in alerts:
        key = "|".join(
            [
                alert.rule.id,
                alert.first_seen.isoformat(),
                json.dumps(alert.group, sort_keys=True),
                alert.evidence[0].origin if alert.evidence else "",
            ]
        )
        anchor = "a-" + hashlib.sha1(key.encode("utf-8", "backslashreplace")).hexdigest()[:12]
        unique, n = anchor, 2
        while unique in seen:
            unique, n = f"{anchor}-{n}", n + 1
        seen.add(unique)
        anchors.append(unique)
    return anchors


def safe_url(value: str) -> str | None:
    """A rule reference as a link only when it is a web address (no ``javascript:``)."""
    return value if re.match(r"^https?://[^\s\"'<>]+$", value) else None


def render_json(report: Report) -> str:
    return json.dumps(to_dict(report), indent=2, ensure_ascii=False) + "\n"


def to_dict(report: Report) -> dict[str, Any]:
    """A plain, JSON-ready view of the report (datetimes as ISO 8601 UTC strings)."""
    data = _plain(report)
    data["alert_count"] = report.alert_count
    return data


def rule_path(path: str) -> str:
    """Where a rule comes from, without the absolute path of the install or home folder.

    Shipped rules become ``vigie/rules/<folder>/<file>``, other rules their file name.
    """
    if not path:
        return ""
    try:
        return "vigie/rules/" + Path(path).resolve().relative_to(RULES_DIR.resolve()).as_posix()
    except ValueError:
        return Path(path).name


def _plain(value: Any) -> Any:
    if isinstance(value, RuleMeta):
        return {**_fields(value), "path": rule_path(value.path)}
    if isinstance(value, datetime):
        return value.isoformat().replace("+00:00", "Z")
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return _fields(value)
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


def _fields(value: Any) -> dict[str, Any]:
    return {f.name: _plain(getattr(value, f.name)) for f in dataclasses.fields(value)}
