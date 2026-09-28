"""Render a report model as Markdown, self-contained HTML, or JSON.

Log content is attacker-controlled (user names, command lines, task XML), so
every value coming from an event is escaped: HTML with Jinja2's autoescaping,
Markdown with :func:`md`, which neutralizes table and formatting characters.
"""

from __future__ import annotations

import dataclasses
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, StrictUndefined

from vigie.models import LEVELS, RuleMeta
from vigie.report.builder import Report
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
    env.globals["LEVELS"] = LEVELS
    return env


def render_markdown(report: Report) -> str:
    return _environment(autoescape=False).get_template("report.md.j2").render(report=report)


def render_html(report: Report) -> str:
    return _environment(autoescape=True).get_template("report.html.j2").render(report=report)


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
