"""Propose the MITRE mitigations of controls that name none, from their wording.

An organization's own questionnaire rarely names MITRE ids: "Les comptes
administrateurs passent par un bastion" means M1026 Privileged Account
Management, but says so in its own words. ``suggest`` reads the title and the
description of a control and looks for the words and phrases, in English and
French, listed for each mitigation in ``data/keywords.json``:

- matching ignores case, accents and punctuation, and works on whole words;
- a phrase found counts one point per word, plus one;
- a mitigation of MITRE ATLAS marked ``ai`` is proposed only when the control
  speaks of AI (a word of ``context``), or when the phrase found does;
- the mitigations scoring 2 or more are proposed, at most three, best first;
  from 4 points the proposal is *likely*, below it *possible*.

It is a reading aid, not a classifier: every proposal says which words it rests
on, and the page and the CSV written by ``vigie assess --map`` let a person
check them. The same rules run in the page (``templates/_assess.js.j2``).
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass, replace
from functools import lru_cache
from importlib import resources
from typing import Any

from vigie.assess.questionnaire import Control, Questionnaire

MIN_SCORE = 2
LIKELY_FROM = 4
MAX_SUGGESTIONS = 3


@dataclass(frozen=True)
class Suggestion:
    mitigation: str
    score: int
    terms: tuple[str, ...]  # the words found in the control

    @property
    def confidence(self) -> str:
        return "likely" if self.score >= LIKELY_FROM else "possible"


@dataclass(frozen=True)
class Mapped:
    """A control of the questionnaire and what ``map_questionnaire`` did with it."""

    control: Control
    suggestions: tuple[Suggestion, ...]  # empty when the control named its ids already


def normalize(text: str) -> str:
    """Lowercase words without accents and plural marks, separated by single spaces."""
    text = unicodedata.normalize("NFD", text.lower())
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Mn")
    return " ".join(_singular(word) for word in re.findall(r"[a-z0-9]+", text))


def _singular(word: str) -> str:
    # "sauvegardes" and "sauvegarde", "reseaux" and "reseau" match each other.
    if len(word) > 3 and (word.endswith("s") or word.endswith("eaux")):
        return word[:-1]
    return word


@lru_cache(maxsize=1)
def raw_keywords() -> dict[str, Any]:
    """``data/keywords.json`` as written (the page normalizes it the same way)."""
    path = resources.files("vigie.assess").joinpath("data/keywords.json")
    text = path.read_text(encoding="utf-8")
    data: dict[str, Any] = json.loads(text)
    return data


@lru_cache(maxsize=1)
def keywords() -> dict[str, Any]:
    raw = raw_keywords()
    return {
        "context": list(dict.fromkeys(normalize(term) for term in raw["context"])),
        "model_words": list(dict.fromkeys(normalize(term) for term in raw["model_words"])),
        "mitigations": {
            mitigation_id: {
                # normalized form -> the term as written, shown to the user
                "terms": _first_spelling(entry["terms"]),
                "ai": bool(entry.get("ai")),
            }
            for mitigation_id, entry in raw["mitigations"].items()
        },
    }


def _first_spelling(terms: list[str]) -> dict[str, str]:
    spelled: dict[str, str] = {}
    for term in terms:
        spelled.setdefault(normalize(term), term)
    return spelled


def suggest(text: str, known: set[str] | None = None) -> list[Suggestion]:
    """The mitigations ``text`` points to, best first; ``known`` limits them to ids in use."""
    data = keywords()
    padded = f" {normalize(text)} "
    if not padded.strip():
        return []
    has_context = any(f" {term} " in padded for term in data["context"])
    ai_words = set(data["context"]) | set(data["model_words"])
    found = []
    for mitigation_id, entry in data["mitigations"].items():
        if known is not None and mitigation_id not in known:
            continue
        score, terms = 0, []
        for term, written in entry["terms"].items():
            if f" {term} " not in padded:
                continue
            if entry["ai"] and not has_context and not (set(term.split()) & ai_words):
                continue
            score += len(term.split()) + 1
            terms.append(written)
        if score >= MIN_SCORE:
            found.append(Suggestion(mitigation_id, score, tuple(terms)))
    found.sort(key=lambda s: (-s.score, s.mitigation))
    return found[:MAX_SUGGESTIONS]


def map_questionnaire(
    questionnaire: Questionnaire, known: set[str] | None = None
) -> tuple[Questionnaire, list[Mapped]]:
    """Give the controls that name no MITRE id the mitigations their wording points to."""
    controls, report = [], []
    for control in questionnaire.controls:
        if control.mitigations or control.techniques:
            controls.append(control)
            report.append(Mapped(control, ()))
            continue
        found = tuple(suggest(f"{control.title} {control.description}", known))
        mapped = control
        if found:
            mapped = replace(control, mitigations=tuple(s.mitigation for s in found))
        controls.append(mapped)
        report.append(Mapped(mapped, found))
    done = {item.control.id for item in report if item.suggestions}
    warnings = [
        warning
        for warning in questionnaire.warnings
        if not any(f"control {control_id} maps to no " in warning for control_id in done)
    ]
    return replace(questionnaire, controls=controls, warnings=warnings), report
