"""Maturity questionnaires: what controls exist, what they cover, how mature each one is.

A questionnaire is a table with one row per control (a point of control, a
requirement, a security measure) and these columns, in any order:

* ``id``: the control's reference (made up from the row number when missing);
* ``control``: what the control is, in words;
* ``domain`` (optional): a group of controls, such as "Identity and access";
* ``description`` (optional): more detail on the control;
* ``mitigations``: the MITRE mitigations the control implements, ATT&CK
  (``M1032``) or ATLAS (``AML.M0020``), separated by commas or spaces;
* ``techniques`` (optional): MITRE techniques the control counters directly
  (``T1078``, ``AML.T0051``), for mappings made technique by technique;
* ``maturity``: how mature the control is, from 0 (absent) to the top of the
  scale (5 by default); empty when it was not assessed;
* ``notes`` (optional): evidence, comments.

Column names are matched loosely (``Maturity level``, ``Niveau``, ``MITRE``...).
CSV, Excel (.xlsx, first sheet) and JSON files are read with the standard
library only. Vigie ships a generic questionnaire built on the MITRE
mitigations themselves (``vigie assess --template``); a mapping of an
organization's own controls to MITRE mitigations works the same way.
"""

from __future__ import annotations

import csv
import io
import json
import re
import unicodedata
import zipfile
from dataclasses import dataclass, field, replace
from importlib import resources
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

DEFAULT_SCALE = 5
MAX_SCALE = 100
MAX_CONTROLS = 5000
MAX_FILE_BYTES = 20 * 1024 * 1024
LEVEL_NAMES_5 = (
    "Absent",
    "Initial",
    "Partial",
    "Defined",
    "Managed",
    "Optimized",
)
MITIGATION_ID = re.compile(r"\b(AML\.M\d{4}|M\d{4})\b", re.IGNORECASE)
TECHNIQUE_ID = re.compile(r"\b(AML\.T\d{4}(?:\.\d{3})?|T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)
NOT_ASSESSED = {"", "-", "n/a", "na", "n.a.", "none", "?", "nc", "n/c", "not assessed", "nan"}

COLUMNS: dict[str, tuple[str, ...]] = {
    "id": ("id", "ref", "reference", "controlid", "control id", "#", "code", "identifiant"),
    "title": (
        "control",
        "title",
        "question",
        "name",
        "requirement",
        "measure",
        "label",
        "point de controle",
        "controle",
        "intitule",
        "exigence",
        "mesure",
    ),
    "domain": (
        "domain",
        "category",
        "theme",
        "family",
        "section",
        "domaine",
        "categorie",
        "thematique",
        "famille",
    ),
    "description": ("description", "details", "detail", "guidance", "objective", "objectif"),
    "mitigations": (
        "mitigations",
        "mitigation",
        "mitre",
        "mitre mitigations",
        "mitre ids",
        "mapping",
        "mitre mapping",
        "mesures mitre",
    ),
    "techniques": ("techniques", "technique", "mitre techniques", "attack", "attack techniques"),
    "maturity": (
        "maturity",
        "maturity level",
        "level",
        "score",
        "current",
        "current level",
        "niveau",
        "niveau de maturite",
        "maturite",
        "note",
    ),
    "notes": ("notes", "note de l'auditeur", "comment", "comments", "commentaire", "evidence"),
}


class QuestionnaireError(ValueError):
    """A questionnaire that cannot be read."""


@dataclass(frozen=True)
class Control:
    id: str
    title: str
    domain: str = ""
    description: str = ""
    mitigations: tuple[str, ...] = ()
    techniques: tuple[str, ...] = ()
    maturity: float | None = None
    notes: str = ""

    @property
    def maps_to_something(self) -> bool:
        return bool(self.mitigations or self.techniques)


@dataclass
class Questionnaire:
    controls: list[Control]
    scale: int = DEFAULT_SCALE
    title: str = ""
    source: str = ""
    warnings: list[str] = field(default_factory=list)

    @property
    def answered(self) -> int:
        return sum(1 for control in self.controls if control.maturity is not None)

    def with_answers(self, answers: dict[str, float | None]) -> Questionnaire:
        """A copy with the maturity of some controls set (by id)."""
        controls = [
            replace(control, maturity=answers[control.id]) if control.id in answers else control
            for control in self.controls
        ]
        return Questionnaire(controls, self.scale, self.title, self.source, list(self.warnings))


def level_names(scale: int) -> tuple[str, ...]:
    """Names of the levels 0..scale; the 0-5 names on a 0-5 scale, numbers otherwise."""
    if scale == DEFAULT_SCALE:
        return LEVEL_NAMES_5
    return tuple(str(level) for level in range(scale + 1))


def generic() -> Questionnaire:
    """The questionnaire shipped with Vigie: one control per MITRE mitigation."""
    text = (resources.files("vigie.assess") / "data" / "questionnaire.csv").read_text(
        encoding="utf-8"
    )
    questionnaire = parse_csv(text, source="generic")
    questionnaire.title = "Generic questionnaire on the MITRE ATT&CK and ATLAS mitigations"
    return questionnaire


def load(path: str | Path, scale: int | None = None, unmapped_ok: bool = False) -> Questionnaire:
    """Read a questionnaire from a CSV, Excel (.xlsx) or JSON file.

    With ``unmapped_ok``, a table without any MITRE column is accepted: its controls
    are then mapped from their wording (``vigie.assess.suggest``).
    """
    path = Path(path)
    if not path.is_file():
        raise QuestionnaireError(f"{path}: no such file")
    if path.stat().st_size > MAX_FILE_BYTES:
        raise QuestionnaireError(f"{path.name}: the file is larger than 20 MB")
    suffix = path.suffix.lower()
    if suffix in (".xlsx", ".xlsm"):
        rows = read_xlsx(path.read_bytes())
        questionnaire = from_rows(rows, scale=scale, source=path.name, unmapped_ok=unmapped_ok)
    elif suffix == ".json":
        questionnaire = parse_json(
            path.read_text(encoding="utf-8-sig"), scale, path.name, unmapped_ok=unmapped_ok
        )
    elif suffix in (".csv", ".tsv", ".txt"):
        questionnaire = parse_csv(
            _decode(path.read_bytes()), scale=scale, source=path.name, unmapped_ok=unmapped_ok
        )
    else:
        raise QuestionnaireError(
            f"{path.name}: use a .csv, .xlsx or .json file (this one is {suffix or 'unknown'})"
        )
    if not questionnaire.title:
        questionnaire.title = path.stem
    return questionnaire


def parse_csv(
    text: str, scale: int | None = None, source: str = "", unmapped_ok: bool = False
) -> Questionnaire:
    sample = text[:4096]
    try:
        dialect: Any = csv.Sniffer().sniff(sample, delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    rows = [row for row in csv.reader(io.StringIO(text), dialect)]
    return from_rows(rows, scale=scale, source=source, unmapped_ok=unmapped_ok)


def parse_json(
    text: str, scale: int | None = None, source: str = "", unmapped_ok: bool = False
) -> Questionnaire:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise QuestionnaireError(f"{source or 'JSON'}: not valid JSON ({exc.msg})") from exc
    title = ""
    if isinstance(data, dict):
        title = str(data.get("title", ""))
        if scale is None and data.get("scale") is not None:
            scale = _scale(data["scale"])
        items = data.get("controls")
    else:
        items = data
    if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
        raise QuestionnaireError(
            f'{source or "JSON"}: expected a list of controls, or an object with a "controls" list'
        )
    keys: list[str] = []
    for item in items:
        for key in item:
            if key not in keys:
                keys.append(key)
    rows: list[list[str]] = [keys]
    for item in items:
        rows.append([_cell(item.get(key)) for key in keys])
    questionnaire = from_rows(rows, scale=scale, source=source, unmapped_ok=unmapped_ok)
    questionnaire.title = title
    return questionnaire


def from_rows(
    rows: list[list[str]],
    scale: int | None = None,
    source: str = "",
    unmapped_ok: bool = False,
) -> Questionnaire:
    """Build a questionnaire from table rows, the first recognizable one being the header."""
    rows = [[str(cell).strip() for cell in row] for row in rows]
    header_index, columns = _find_header(rows)
    if "title" not in columns and "id" not in columns:
        raise QuestionnaireError(
            f"{source or 'the table'}: no column names a control (expected a column such as "
            '"control" or "id")'
        )
    mapped_columns = "mitigations" in columns or "techniques" in columns
    if not mapped_columns and not unmapped_ok:
        raise QuestionnaireError(
            f"{source or 'the table'}: no column maps the controls to MITRE (expected a "
            '"mitigations" column, such as M1032 or AML.M0020, or a "techniques" column)'
        )
    warnings: list[str] = []
    raw: list[dict[str, str]] = []
    for number, row in enumerate(rows[header_index + 1 :], start=header_index + 2):
        if not any(row):
            continue
        values = {key: row[index] if index < len(row) else "" for key, index in columns.items()}
        values["_row"] = str(number)
        raw.append(values)
        if len(raw) > MAX_CONTROLS:
            raise QuestionnaireError(f"{source}: more than {MAX_CONTROLS} controls")

    values_seen = [_number(item.get("maturity", "")) for item in raw]
    highest = max((value for value in values_seen if value is not None), default=0)
    if scale is None:
        scale = DEFAULT_SCALE
        if highest > DEFAULT_SCALE:
            raise QuestionnaireError(
                f"{source}: maturity levels go up to {highest:g}, above the default 0-5 scale; "
                "give the top of your scale (--scale)"
            )
    controls: list[Control] = []
    seen_ids: set[str] = set()
    for item in raw:
        row = item["_row"]
        control_id = item.get("id") or f"C{len(controls) + 1}"
        if control_id in seen_ids:
            warnings.append(f"row {row}: control id {control_id} appears twice, renamed")
            control_id = f"{control_id}-{row}"
        seen_ids.add(control_id)
        maturity = _number(item.get("maturity", ""))
        text = item.get("maturity", "").strip()
        if maturity is None and text.lower() not in NOT_ASSESSED:
            warnings.append(f"row {row}: maturity {text!r} is not a number, left unassessed")
        if maturity is not None and not 0 <= maturity <= scale:
            warnings.append(
                f"row {row}: maturity {maturity:g} is outside 0-{scale}, left unassessed"
            )
            maturity = None
        mitigations = _ids(MITIGATION_ID, item.get("mitigations", ""))
        techniques = _ids(TECHNIQUE_ID, item.get("techniques", ""))
        control = Control(
            id=control_id,
            title=item.get("title") or control_id,
            domain=item.get("domain", ""),
            description=item.get("description", ""),
            mitigations=mitigations,
            techniques=techniques,
            maturity=maturity,
            notes=item.get("notes", ""),
        )
        if not control.maps_to_something and mapped_columns:
            warnings.append(
                f"row {row}: control {control_id} maps to no MITRE mitigation or technique, "
                "it does not count"
            )
        controls.append(control)
    if not controls:
        raise QuestionnaireError(f"{source or 'the table'}: no control found under the header")
    return Questionnaire(controls=controls, scale=scale, source=source, warnings=warnings)


def to_rows(questionnaire: Questionnaire) -> list[list[str]]:
    header = ["id", "domain", "control", "description", "mitigations", "techniques"]
    header += ["maturity", "notes"]
    rows = [header]
    for control in questionnaire.controls:
        rows.append(
            [
                control.id,
                control.domain,
                control.title,
                control.description,
                " ".join(control.mitigations),
                " ".join(control.techniques),
                "" if control.maturity is None else f"{control.maturity:g}",
                control.notes,
            ]
        )
    return rows


def to_csv(questionnaire: Questionnaire) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerows(to_rows(questionnaire))
    return buffer.getvalue()


def read_xlsx(data: bytes) -> list[list[str]]:
    """The cells of the first sheet of an .xlsx workbook, as rows of text."""
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise QuestionnaireError("not an Excel .xlsx file") from exc
    with archive:
        names = set(archive.namelist())
        ns = {
            "m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
            "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
            "p": "http://schemas.openxmlformats.org/package/2006/relationships",
        }
        sheet_path = "xl/worksheets/sheet1.xml"
        if "xl/workbook.xml" in names and "xl/_rels/workbook.xml.rels" in names:
            workbook = _xml(archive, "xl/workbook.xml")
            first = workbook.find("m:sheets/m:sheet", ns)
            rels = _xml(archive, "xl/_rels/workbook.xml.rels")
            if first is not None:
                rel_id = first.get(f"{{{ns['r']}}}id")
                for rel in rels.findall("p:Relationship", ns):
                    if rel.get("Id") == rel_id:
                        target = rel.get("Target", "").lstrip("/")
                        sheet_path = target if target.startswith("xl/") else f"xl/{target}"
        if sheet_path not in names:
            raise QuestionnaireError("the workbook has no readable sheet")
        shared: list[str] = []
        if "xl/sharedStrings.xml" in names:
            for item in _xml(archive, "xl/sharedStrings.xml").findall("m:si", ns):
                shared.append("".join(text.text or "" for text in item.iter(f"{{{ns['m']}}}t")))
        sheet = _xml(archive, sheet_path)
        rows: list[list[str]] = []
        for row in sheet.iter(f"{{{ns['m']}}}row"):
            cells: dict[int, str] = {}
            for cell in row.findall("m:c", ns):
                column = _column_index(cell.get("r", ""), len(cells))
                kind = cell.get("t", "")
                value = cell.find("m:v", ns)
                if kind == "s" and value is not None and value.text is not None:
                    index = int(value.text)
                    text = shared[index] if 0 <= index < len(shared) else ""
                elif kind == "inlineStr":
                    text = "".join(t.text or "" for t in cell.iter(f"{{{ns['m']}}}t"))
                elif value is not None and value.text is not None:
                    text = value.text
                    if kind in ("", "n") and re.fullmatch(r"-?\d+\.0+", text):
                        text = text.split(".")[0]
                else:
                    text = ""
                cells[column] = text
            if cells:
                width = max(cells) + 1
                rows.append([cells.get(index, "") for index in range(width)])
        return rows


def _xml(archive: zipfile.ZipFile, name: str) -> ElementTree.Element:
    info = archive.getinfo(name)
    if info.file_size > MAX_FILE_BYTES * 5:
        raise QuestionnaireError("the workbook is too large")
    return ElementTree.fromstring(archive.read(name))


def _column_index(reference: str, fallback: int) -> int:
    letters = "".join(char for char in reference if char.isalpha())
    if not letters:
        return fallback
    index = 0
    for char in letters.upper():
        index = index * 26 + (ord(char) - 64)
    return index - 1


def _find_header(rows: list[list[str]]) -> tuple[int, dict[str, int]]:
    best = (0, {})
    for index, row in enumerate(rows[:30]):
        columns = _columns(row)
        if len(columns) > len(best[1]):
            best = (index, columns)
        if {"mitigations", "maturity"} <= columns.keys() or {"techniques", "maturity"} <= set(
            columns
        ):
            return index, columns
    return best


def _columns(header: list[str]) -> dict[str, int]:
    """Which column of a header row holds what: exact names first, then names that start
    with a known one ("Maturity level (0-5)")."""
    keys = [_normalize(name) for name in header]
    found: dict[str, int] = {}
    for exact in (True, False):
        for index, key in enumerate(keys):
            if not key or index in found.values():
                continue
            for column, aliases in COLUMNS.items():
                if column in found:
                    continue
                if (key in aliases) if exact else any(key.startswith(a + " ") for a in aliases):
                    found[column] = index
                    break
    return found


def _normalize(name: str) -> str:
    text = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode()
    text = re.sub(r"[_\-/()\[\]:.'\u2019]+", " ", text.lower())
    return " ".join(text.split())


def _ids(pattern: re.Pattern[str], text: str) -> tuple[str, ...]:
    found: list[str] = []
    for match in pattern.finditer(text):
        value = match.group(1).upper()
        if value not in found:
            found.append(value)
    return tuple(found)


def _number(text: str) -> float | None:
    value = text.strip().replace(",", ".")
    if value.lower() in NOT_ASSESSED:
        return None
    match = re.fullmatch(r"(-?\d+(?:\.\d+)?)\s*(?:/\s*\d+)?", value)
    if not match:
        return None
    number = float(match.group(1))
    return int(number) if number.is_integer() else round(number, 2)


def _scale(value: Any) -> int:
    try:
        scale = int(value)
    except (TypeError, ValueError) as exc:
        raise QuestionnaireError(f"the scale must be a whole number, not {value!r}") from exc
    if not 1 <= scale <= MAX_SCALE:
        raise QuestionnaireError(f"the scale must be between 1 and {MAX_SCALE}")
    return scale


def check_scale(value: int) -> int:
    return _scale(value)


def _cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list | tuple):
        return " ".join(str(item) for item in value)
    return str(value)


def _decode(data: bytes) -> str:
    for encoding in ("utf-8-sig", "cp1252", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")
