"""Parser for the ``condition`` of a Sigma detection.

Grammar (lowest to highest precedence)::

    expr    := and_expr ("or" and_expr)*
    and_expr:= not_expr ("and" not_expr)*
    not_expr:= "not" not_expr | atom
    atom    := "(" expr ")" | ("1" | "all") "of" (pattern | "them") | name

``pattern`` may use ``*`` (``1 of selection_*``); ``them`` means every
selection whose name does not start with an underscore. The result is a small
tree of nodes evaluated with short-circuit logic, so a selection is only
tested when its result can change the outcome.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass

from vigie.sigma.matcher import SigmaError

Resolver = Callable[[str], bool]

_TOKEN = re.compile(r"\s*(?:(\()|(\))|([^\s()]+))")
_KEYWORDS = {"and", "or", "not", "of", "them"}


class Node:
    """A node of a parsed condition."""

    def evaluate(self, resolve: Resolver) -> bool:
        raise NotImplementedError


@dataclass(frozen=True)
class Ref(Node):
    name: str

    def evaluate(self, resolve: Resolver) -> bool:
        return resolve(self.name)


@dataclass(frozen=True)
class And(Node):
    items: tuple[Node, ...]

    def evaluate(self, resolve: Resolver) -> bool:
        return all(item.evaluate(resolve) for item in self.items)


@dataclass(frozen=True)
class Or(Node):
    items: tuple[Node, ...]

    def evaluate(self, resolve: Resolver) -> bool:
        return any(item.evaluate(resolve) for item in self.items)


@dataclass(frozen=True)
class Not(Node):
    item: Node

    def evaluate(self, resolve: Resolver) -> bool:
        return not self.item.evaluate(resolve)


def parse_condition(condition: str | Sequence[str], names: Iterable[str]) -> Node:
    """Parse ``condition`` against the selection ``names`` defined by the rule.

    A list of conditions (older Sigma style) means any of them.
    """
    known = list(names)
    if isinstance(condition, str):
        return _Parser(condition, known).parse()
    if isinstance(condition, list) and condition and all(isinstance(c, str) for c in condition):
        return _combine(Or, [_Parser(c, known).parse() for c in condition])
    raise SigmaError("condition must be a string or a list of strings")


def _combine(kind: type[And] | type[Or], items: list[Node]) -> Node:
    if len(items) == 1:
        return items[0]
    flat: list[Node] = []
    for item in items:
        flat.extend(item.items if isinstance(item, kind) else [item])
    return kind(tuple(flat))


class _Parser:
    def __init__(self, text: str, names: list[str]) -> None:
        if "|" in text:
            raise SigmaError(
                "aggregations in conditions ('| count() ...') are not supported, "
                "use a Sigma correlation rule instead"
            )
        self.text = text
        self.names = names
        self.tokens = self._tokenize(text)
        self.position = 0

    @staticmethod
    def _tokenize(text: str) -> list[str]:
        tokens = [m.group(1) or m.group(2) or m.group(3) for m in _TOKEN.finditer(text)]
        if not tokens:
            raise SigmaError("empty condition")
        return tokens

    def parse(self) -> Node:
        node = self._or()
        if self.position != len(self.tokens):
            raise SigmaError(
                f"unexpected '{self.tokens[self.position]}' in condition '{self.text}'"
            )
        return node

    def _peek(self) -> str | None:
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def _take(self) -> str:
        token = self._peek()
        if token is None:
            raise SigmaError(f"condition '{self.text}' ends unexpectedly")
        self.position += 1
        return token

    def _is(self, word: str) -> bool:
        token = self._peek()
        return token is not None and token.lower() == word

    def _or(self) -> Node:
        items = [self._and()]
        while self._is("or"):
            self._take()
            items.append(self._and())
        return _combine(Or, items)

    def _and(self) -> Node:
        items = [self._not()]
        while self._is("and"):
            self._take()
            items.append(self._not())
        return _combine(And, items)

    def _not(self) -> Node:
        if self._is("not"):
            self._take()
            return Not(self._not())
        return self._atom()

    def _atom(self) -> Node:
        token = self._take()
        if token == "(":
            node = self._or()
            if self._take() != ")":
                raise SigmaError(f"missing ')' in condition '{self.text}'")
            return node
        if token == ")":
            raise SigmaError(f"unexpected ')' in condition '{self.text}'")
        if token.lower() in ("1", "all") and self._is("of"):
            self._take()
            return self._quantifier(token.lower(), self._take())
        if token.lower() in _KEYWORDS:
            raise SigmaError(f"unexpected '{token}' in condition '{self.text}'")
        if token not in self.names:
            raise SigmaError(f"condition references unknown selection '{token}'")
        return Ref(token)

    def _quantifier(self, quantifier: str, target: str) -> Node:
        if target.lower() == "them":
            selected = [name for name in self.names if not name.startswith("_")]
        elif target in ("(", ")"):
            raise SigmaError(f"'{quantifier} of' needs a name pattern in '{self.text}'")
        else:
            selected = [name for name in self.names if fnmatch.fnmatchcase(name, target)]
        if not selected:
            raise SigmaError(f"'{quantifier} of {target}' matches no selection")
        refs: list[Node] = [Ref(name) for name in selected]
        return _combine(Or if quantifier == "1" else And, refs)
