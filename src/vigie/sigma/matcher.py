"""Sigma value matching: wildcards, field modifiers and selections.

A Sigma *selection* is either a map of field conditions (all must hold) or a
list of such maps (any may hold), or a list of *keywords* searched in the raw
event text. Each field condition looks like ``Image|endswith: '\\lsass.exe'``:
a field name, optional modifiers, and one value or a list of values (any of
them may match, or all of them with ``|all``).

Everything is compiled once, when the rule is loaded, into small predicate
objects; matching an event then costs no parsing at all.

Semantics follow the Sigma specification:

* string comparisons are case-insensitive unless ``|cased`` is used;
* ``*`` matches any sequence and ``?`` any single character; ``\\`` escapes
  ``*``, ``?`` and ``\\`` itself, any other backslash is literal;
* ``|re`` is a Python regular expression, case-sensitive, searched anywhere
  in the value (``|i``, ``|m`` and ``|s`` set the usual flags);
* a ``null`` value matches a missing or empty field.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

FieldValue = str | tuple[str, ...] | None
Lookup = Callable[[str], FieldValue]
Test = Callable[[str], bool]


class SigmaError(ValueError):
    """A rule is invalid, or uses a Sigma feature Vigie does not support."""


# Modifiers that decide *how* a value is compared. At most one per field.
MATCH_MODIFIERS = frozenset(
    {"contains", "startswith", "endswith", "re", "cidr", "exists", "lt", "lte", "gt", "gte"}
)
# Flags that refine the comparison.
FLAG_MODIFIERS = frozenset({"all", "cased", "windash", "i", "m", "s"})
REGEX_FLAGS = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}

# Windows command-line options accept -x, /x and Unicode dashes alike.
WINDASH_CHARS = "-/\u2013\u2014\u2015"  # hyphen, slash, en dash, em dash, bar
WINDASH_CLASS = "[" + re.escape(WINDASH_CHARS) + "]"


@dataclass(frozen=True)
class FieldCondition:
    """One ``field|modifiers: value(s)`` line of a selection."""

    field: str
    tests: tuple[Test, ...]
    require_all: bool = False
    matches_missing: bool = False
    exists: bool | None = None

    def matches(self, value: FieldValue) -> bool:
        if self.exists is not None:
            return (value is not None) == self.exists
        if value is None:
            return self.matches_missing
        values = value if isinstance(value, tuple) else (value,)

        def hit(test: Test) -> bool:
            return any(test(item) for item in values)

        if self.require_all:
            return all(hit(test) for test in self.tests)
        return any(hit(test) for test in self.tests)


@dataclass(frozen=True)
class Selection:
    """A named detection item: field conditions, alternatives of them, or keywords."""

    name: str
    alternatives: tuple[tuple[FieldCondition, ...], ...] = ()
    keywords: tuple[Test, ...] = ()

    def matches(self, lookup: Lookup, raw: str) -> bool:
        if self.keywords:
            return any(test(raw) for test in self.keywords)
        return any(
            all(condition.matches(lookup(condition.field)) for condition in conditions)
            for conditions in self.alternatives
        )


def compile_selection(name: str, definition: Any) -> Selection:
    """Compile the YAML definition of one selection."""
    if isinstance(definition, Mapping):
        return Selection(name, alternatives=(_compile_map(name, definition),))
    if isinstance(definition, list) and definition:
        if all(isinstance(item, Mapping) for item in definition):
            return Selection(name, alternatives=tuple(_compile_map(name, m) for m in definition))
        if all(_is_scalar(item) for item in definition):
            return Selection(name, keywords=tuple(_keyword_test(item) for item in definition))
        raise SigmaError(f"selection '{name}' mixes keywords and field maps")
    if _is_scalar(definition) and definition is not None:
        return Selection(name, keywords=(_keyword_test(definition),))
    raise SigmaError(f"selection '{name}' is empty or has an invalid type")


def compile_field(spec: str, value: Any) -> FieldCondition:
    """Compile ``field|mod1|mod2`` and its value (a scalar or a list) into a condition."""
    field, *modifiers = spec.split("|")
    if not field:
        raise SigmaError(f"'{spec}': keyword modifiers without a field are not supported")
    unknown = [m for m in modifiers if m not in MATCH_MODIFIERS | FLAG_MODIFIERS]
    if unknown:
        raise SigmaError(f"'{spec}': unsupported modifier(s) {', '.join(unknown)}")
    kinds = [m for m in modifiers if m in MATCH_MODIFIERS]
    if len(kinds) > 1:
        raise SigmaError(f"'{spec}': conflicting modifiers {', '.join(kinds)}")
    kind = kinds[0] if kinds else "equals"
    flags = {m for m in modifiers if m in FLAG_MODIFIERS}
    if flags & {"i", "m", "s"} and kind != "re":
        raise SigmaError(f"'{spec}': i, m and s only apply to the re modifier")

    values = value if isinstance(value, list) else [value]
    if not values:
        raise SigmaError(f"'{spec}': empty value list")

    if kind == "exists":
        if len(values) != 1 or not isinstance(values[0], bool):
            raise SigmaError(f"'{spec}': exists expects true or false")
        return FieldCondition(field, (), exists=values[0])

    tests: list[Test] = []
    matches_missing = False
    for item in values:
        if item is None:
            if kind != "equals":
                raise SigmaError(f"'{spec}': null cannot be combined with {kind}")
            matches_missing = True
            tests.append(_is_empty)
        else:
            tests.append(_value_test(spec, kind, flags, item))
    return FieldCondition(
        field, tuple(tests), require_all="all" in flags, matches_missing=matches_missing
    )


def wildcard_to_regex(value: str, windash: bool = False) -> str:
    """Translate a Sigma string with ``*``/``?`` wildcards into a regex fragment."""
    out: list[str] = []
    i = 0
    while i < len(value):
        char = value[i]
        if char == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            out.append(re.escape(value[i + 1]))
            i += 2
            continue
        if char == "*":
            out.append(".*")
        elif char == "?":
            out.append(".")
        elif windash and char in WINDASH_CHARS and (i == 0 or value[i - 1] == " "):
            out.append(WINDASH_CLASS)
        else:
            out.append(re.escape(char))
        i += 1
    return "".join(out)


def _compile_map(name: str, definition: Mapping[str, Any]) -> tuple[FieldCondition, ...]:
    if not definition:
        raise SigmaError(f"selection '{name}' is an empty map")
    return tuple(compile_field(str(spec), value) for spec, value in definition.items())


def _is_scalar(value: Any) -> bool:
    return value is None or isinstance(value, (str, int, float, bool))


def _is_empty(value: str) -> bool:
    return value == ""


def _as_text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _keyword_test(value: Any) -> Test:
    # Keywords are searched anywhere in the raw event text.
    pattern = re.compile(".*" + wildcard_to_regex(_as_text(value)) + ".*", re.I | re.S)
    return lambda text: pattern.fullmatch(text) is not None


def _value_test(spec: str, kind: str, flags: set[str], value: Any) -> Test:
    if kind == "re":
        regex_flags = 0
        for flag in flags & set(REGEX_FLAGS):
            regex_flags |= REGEX_FLAGS[flag]
        try:
            pattern = re.compile(str(value), regex_flags)
        except re.error as exc:
            raise SigmaError(f"'{spec}': invalid regular expression ({exc})") from exc
        return lambda text: pattern.search(text) is not None

    if kind == "cidr":
        try:
            network = ipaddress.ip_network(str(value), strict=False)
        except ValueError as exc:
            raise SigmaError(f"'{spec}': invalid network {value!r}") from exc
        return lambda text: _in_network(text, network)

    if kind in ("lt", "lte", "gt", "gte"):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise SigmaError(f"'{spec}': {kind} expects a number")
        return _numeric_test(kind, float(value))

    core = wildcard_to_regex(_as_text(value), windash="windash" in flags)
    if kind in ("contains", "endswith"):
        core = ".*" + core
    if kind in ("contains", "startswith"):
        core = core + ".*"
    regex_flags = re.DOTALL if "cased" in flags else re.DOTALL | re.IGNORECASE
    pattern = re.compile(core, regex_flags)
    return lambda text: pattern.fullmatch(text) is not None


def _in_network(text: str, network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    try:
        return ipaddress.ip_address(text.strip()) in network
    except ValueError:
        return False


def _numeric_test(kind: str, limit: float) -> Test:
    compare: dict[str, Callable[[float], bool]] = {
        "lt": lambda number: number < limit,
        "lte": lambda number: number <= limit,
        "gt": lambda number: number > limit,
        "gte": lambda number: number >= limit,
    }

    def test(text: str) -> bool:
        try:
            return compare[kind](float(text))
        except ValueError:
            return False

    return test
