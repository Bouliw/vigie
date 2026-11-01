"""Map Sigma ``owasp.*`` tags to the OWASP Top 10 lists for LLM and agentic applications.

The OWASP GenAI Security Project publishes two lists of the risks of AI
applications, which the AI rules of Vigie map to next to MITRE ATLAS:

* the OWASP Top 10 for LLM Applications 2025, ``LLM01:2025`` to ``LLM10:2025``;
* the OWASP Top 10 for Agentic Applications 2026 (published in December 2025),
  ``ASI01`` to ``ASI10``.

Sigma defines no tag namespace for them, so Vigie's rules use their own,
written like ``atlas.*``: ``owasp.llm01`` for LLM01:2025, ``owasp.asi04`` for
ASI04. ATLAS describes how an attack is carried out, step by step; the OWASP
lists name the weakness of the application it exploits, which is how many
security teams track the risks of their AI applications.

Only the ids, names and links of the entries are kept, from the official pages
of the OWASP GenAI Security Project (genai.owasp.org), whose content is
licensed under CC BY-SA 4.0.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache

TAG_PREFIX = "owasp."
ITEM_TAG = re.compile(r"^(llm|asi)(\d{2})$")
ATTRIBUTION = (
    "OWASP Top 10 for LLM Applications and for Agentic Applications: "
    "OWASP GenAI Security Project, licensed under CC BY-SA 4.0."
)

_LLM_2025 = (
    ("LLM01:2025", "Prompt Injection", "llm01-prompt-injection"),
    (
        "LLM02:2025",
        "Sensitive Information Disclosure",
        "llm022025-sensitive-information-disclosure",
    ),
    ("LLM03:2025", "Supply Chain", "llm032025-supply-chain"),
    ("LLM04:2025", "Data and Model Poisoning", "llm042025-data-and-model-poisoning"),
    ("LLM05:2025", "Improper Output Handling", "llm052025-improper-output-handling"),
    ("LLM06:2025", "Excessive Agency", "llm062025-excessive-agency"),
    ("LLM07:2025", "System Prompt Leakage", "llm072025-system-prompt-leakage"),
    ("LLM08:2025", "Vector and Embedding Weaknesses", "llm082025-vector-and-embedding-weaknesses"),
    ("LLM09:2025", "Misinformation", "llm092025-misinformation"),
    ("LLM10:2025", "Unbounded Consumption", "llm102025-unbounded-consumption"),
)
# The agentic list has no page per entry: every entry links to the document.
_AGENTIC_2026 = (
    ("ASI01", "Agent Goal Hijack"),
    ("ASI02", "Tool Misuse and Exploitation"),
    ("ASI03", "Identity and Privilege Abuse"),
    ("ASI04", "Agentic Supply Chain Vulnerabilities"),
    ("ASI05", "Unexpected Code Execution"),
    ("ASI06", "Memory and Context Poisoning"),
    ("ASI07", "Insecure Inter-Agent Communication"),
    ("ASI08", "Cascading Failures"),
    ("ASI09", "Human-Agent Trust Exploitation"),
    ("ASI10", "Rogue Agents"),
)
LLM_URL = "https://genai.owasp.org/llm-top-10/"
AGENTIC_URL = "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"


@dataclass(frozen=True)
class OwaspItem:
    """One entry of an OWASP Top 10 list."""

    id: str  # "LLM01:2025", "ASI04"
    name: str
    url: str
    list: str  # key of its list: "llm" or "asi"

    @property
    def display_name(self) -> str:
        """``"LLM01:2025 Prompt Injection"``, as OWASP writes it."""
        return f"{self.id} {self.name}"


@dataclass(frozen=True)
class OwaspList:
    """An OWASP Top 10 list, its entries in their published order."""

    key: str  # "llm", "asi": the prefix of the tags
    title: str
    edition: str  # the year of the list: "2025"
    url: str
    items: tuple[OwaspItem, ...]


@dataclass(frozen=True)
class OwaspMapping:
    """What a rule's ``owasp.*`` tags resolve to."""

    items: tuple[OwaspItem, ...] = ()  # in list order: the LLM list first
    unknown: tuple[str, ...] = ()  # owasp.* tags that match no entry


class OwaspData:
    """The OWASP Top 10 lists Vigie maps its AI rules to."""

    def __init__(self, lists: Iterable[OwaspList]) -> None:
        self.lists: tuple[OwaspList, ...] = tuple(lists)
        self.copyright = ATTRIBUTION
        self._items = {
            (owasp.key, int(entry.id[3:5])): (owasp, entry)
            for owasp in self.lists
            for entry in owasp.items
        }
        self._rank = {entry.id: rank for rank, entry in enumerate(self.items())}

    def items(self) -> tuple[OwaspItem, ...]:
        """Every entry, list after list, in published order."""
        return tuple(entry for owasp in self.lists for entry in owasp.items)

    def item(self, item_id: str) -> OwaspItem | None:
        """Look an entry up by id, case-insensitive: ``LLM01:2025``, ``llm01``, ``ASI04``."""
        number, _, edition = item_id.lower().partition(":")
        match = ITEM_TAG.match(number)
        found = self._items.get((match[1], int(match[2]))) if match else None
        if found is None:
            return None
        owasp, entry = found
        if edition and edition != owasp.edition:
            return None  # another edition of the list: LLM01:2023 is not LLM01:2025
        return entry

    def list_of(self, entry: OwaspItem) -> OwaspList:
        return next(owasp for owasp in self.lists if owasp.key == entry.list)

    def map_tags(self, tags: Iterable[str]) -> OwaspMapping:
        """Resolve the ``owasp.*`` tags of a rule; other tags are ignored."""
        found: dict[str, OwaspItem] = {}
        unknown: list[str] = []
        for tag in tags:
            lowered = tag.lower()
            if not lowered.startswith(TAG_PREFIX):
                continue
            value = lowered.removeprefix(TAG_PREFIX)
            entry = self.item(value) if ITEM_TAG.match(value) else None
            if entry is None:
                unknown.append(tag)
                continue
            found.setdefault(entry.id, entry)
        return OwaspMapping(
            items=tuple(sorted(found.values(), key=lambda entry: self._rank[entry.id])),
            unknown=tuple(unknown),
        )


def _llm_list() -> OwaspList:
    return OwaspList(
        key="llm",
        title="OWASP Top 10 for LLM Applications 2025",
        edition="2025",
        url=LLM_URL,
        items=tuple(
            OwaspItem(
                id=item_id, name=name, url=f"https://genai.owasp.org/llmrisk/{slug}/", list="llm"
            )
            for item_id, name, slug in _LLM_2025
        ),
    )


def _agentic_list() -> OwaspList:
    return OwaspList(
        key="asi",
        title="OWASP Top 10 for Agentic Applications 2026",
        edition="2026",
        url=AGENTIC_URL,
        items=tuple(
            OwaspItem(id=item_id, name=name, url=AGENTIC_URL, list="asi")
            for item_id, name in _AGENTIC_2026
        ),
    )


@lru_cache(maxsize=1)
def default_owasp_data() -> OwaspData:
    """The two OWASP Top 10 lists, built once."""
    return OwaspData([_llm_list(), _agentic_list()])
