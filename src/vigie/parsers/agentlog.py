"""Parser for the activity logs of AI agents and LLM applications, in JSON Lines.

Each line is one JSON object, in one of three shapes, recognized line by line:

* Vigie's agent log, a vendor-neutral schema with one record per step of a
  conversation or agent run (the README documents every field)::

    {"timestamp": "2026-10-20T09:15:02Z", "session_id": "s-1042", "actor": "alice",
     "type": "tool_call", "tool": "run_shell", "arguments": {"command": "ls"}}

  ``type`` is ``system`` (the system prompt), ``prompt`` (what the user
  wrote), ``response`` (what the model answered), ``tool_call`` (a tool the
  model asked to run), ``tool_result`` (what the tool returned) or
  ``retrieval`` (a passage a retrieval step added to the context);
* OpenAI Chat Completions calls, as API gateways and proxies log them: the
  request body under ``request`` and the response body under ``response`` (or
  a bare ``chat.completion`` object). A call becomes the records above: the
  messages added since the model last answered, then its answer and tool calls;
* Model Context Protocol (MCP) traffic: JSON-RPC 2.0 messages with the time
  they were seen, ``{"timestamp": ..., "message": {...}}``. A ``tools/call``
  request is a ``tool_call``, and its response a ``tool_result``. Each tool of
  a ``tools/list`` answer is a ``tool_definition``: its name, and as content
  its description followed by the descriptions of its parameters, which the
  model reads before it calls anything.

Every record becomes an :class:`~vigie.models.Event` with ``source="agentlog"``
and the record's fields, plus fields Vigie derives for the detection rules:

* ``url`` and ``url_host``: the web addresses found in a tool call's arguments;
* ``image_url`` and ``image_host``: the images a response embeds (Markdown
  ``![...](...)`` or HTML ``<img src=...>``), which a chat client loads by itself;
* ``hidden_text``: text hidden in invisible Unicode "tag" characters, decoded;
* ``pii``: the kinds of personal data found in the text that pass their
  checksum (``payment_card``: issuer range, length and Luhn; ``iban``: ISO 7064
  mod 97). In a response, values the user wrote earlier in the same session
  are left out: a support assistant repeating the card number it was given
  leaks nothing;
* ``system_prompt_echo``: on a response that reproduces, word for word, a large
  part of the system prompt of its session.

The parser keeps, per recent session, the system prompt and the personal data
the user gave, and the MCP calls still waiting for their result, so one
:class:`Reader` reads a whole file, or follows it line by line in
``vigie watch``.
"""

from __future__ import annotations

import json
import re
from collections import OrderedDict
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from vigie.models import Event
from vigie.parsers.base import ParseResult
from vigie.timeutils import UTC, parse_iso8601

SOURCE = "agentlog"
EVENT_TYPES = frozenset({"system", "prompt", "response", "tool_call", "tool_result", "retrieval"})

# Sessions whose system prompt is remembered, and MCP calls waiting for their
# result: the oldest are forgotten first, so memory stays bounded.
MAX_SESSIONS = 10_000
MAX_PENDING_CALLS = 10_000
# How deep the parameters of an MCP tool are read for their descriptions.
MAX_SCHEMA_DEPTH = 10

# A response "echoes" the system prompt when it reproduces runs of at least
# ECHO_WINDOW characters of it (case and spacing aside) that add up to
# ECHO_MIN characters, or to half of a shorter prompt. Quoting one sentence the
# prompt tells the model to say ("I can only help with orders.") is not enough.
ECHO_WINDOW = 60
ECHO_MIN = 200

# Unicode tag characters are invisible. U+E0020 to U+E007E mirror printable
# ASCII, so they can carry text no reader sees ("ASCII smuggling"). Emoji flags
# of subdivisions (England, Scotland, Wales) use them legitimately, after
# U+1F3F4 WAVING BLACK FLAG and up to U+E007F CANCEL TAG.
_TAG_RUN = re.compile("[\U000e0020-\U000e007e]+")
_TAG_FLAG = re.compile("\U0001f3f4[\U000e0020-\U000e007e]+\U000e007f")

_URL = re.compile(r"https?://[^\s\"'<>\\`]+", re.IGNORECASE)
_URL_END = ".,;:!?)]}"
# Images a chat client fetches as soon as it renders the response.
_MARKDOWN_IMAGE = re.compile(r"!\[[^\]\n]*\]\(\s*<?(https?://[^\s)>]+)", re.IGNORECASE)
_HTML_IMAGE = re.compile(r"<img\b[^>]*?\bsrc\s*=\s*[\"']?(https?://[^\"'\s>]+)", re.IGNORECASE)

# Card numbers in groups of four with one kind of separator (or none), and the
# 4-6-5 grouping of 15-digit cards.
_CARD = re.compile(
    r"(?<![\w-])(?:\d{4}([ -]?)\d{4}\1\d{4}\1\d{1,7}|\d{4}([ -]?)\d{6}\2\d{5})(?![\w-])"
)
# Issuer prefixes and lengths of the major card networks: Visa, Mastercard,
# American Express, Discover, JCB, Diners Club, UnionPay. A 16-digit order or
# tracking number passes the Luhn check one time in ten; most do not also fall
# in a card range.
_CARD_RANGES = (
    (re.compile(r"4"), (13, 16, 19)),
    (re.compile(r"5[1-5]|2(?:22[1-9]|2[3-9]\d|[3-6]\d\d|7[01]\d|720)"), (16,)),
    (re.compile(r"3[47]"), (15,)),
    (re.compile(r"6(?:011|5|4[4-9])"), (16, 17, 18, 19)),
    (re.compile(r"35(?:2[89]|[3-8]\d)"), (16, 17, 18, 19)),
    (re.compile(r"3(?:0[0-5]|[689])"), (14, 15, 16)),
    (re.compile(r"62"), (16, 17, 18, 19)),
)
_IBAN = re.compile(r"(?<![\w-])[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?(?![\w-])")
# Numbers that payment and banking documentation uses as examples: a model
# quoting them leaks nothing.
EXAMPLE_NUMBERS = frozenset(
    {
        "4111111111111111",
        "4242424242424242",
        "4000056655665556",
        "4012888888881881",
        "5555555555554444",
        "5105105105105100",
        "2223003122003222",
        "378282246310005",
        "371449635398431",
        "6011111111111117",
        "6011000990139424",
        "3056930009020004",
        "3566002020360505",
        "6200000000000005",
        "GB82WEST12345698765432",
        "DE89370400440532013000",
        "FR7630006000011234567890189",
    }
)

# Keys of the actor and session in records that do not follow Vigie's schema.
_ACTOR_KEYS = ("actor", "user", "user_id", "end_user")
_SESSION_KEYS = ("session_id", "conversation_id", "thread_id")


class Reader:
    """Turn the lines of one agent log into events, in order.

    It remembers what later lines need: the system prompt of each session, to
    recognize it in a response, and the MCP tool calls whose result has not
    arrived yet, to name the tool in the result.
    """

    def __init__(self) -> None:
        self._prompts: OrderedDict[str, _SystemPrompt] = OrderedDict()
        self._given: OrderedDict[str, frozenset[str]] = OrderedDict()
        self._calls: OrderedDict[tuple[str, str], str] = OrderedDict()

    def read_line(self, raw: str, *, origin: str, warnings: list[str]) -> list[Event]:
        """The events of one line; a line that cannot be read adds a warning."""
        text = raw.strip()
        if not text:
            return []
        try:
            record = json.loads(text)
        except json.JSONDecodeError:
            warnings.append(f"{origin}: not a JSON object")
            return []
        dialect = dialect_of(record) if isinstance(record, dict) else None
        if dialect is None:
            warnings.append(f"{origin}: not an AI agent log record")
            return []
        try:
            if dialect == "vigie":
                steps = [_vigie_step(record)]
            elif dialect == "openai":
                steps = _openai_steps(record)
            else:
                steps = self._mcp_steps(record)
        except ValueError as exc:
            warnings.append(f"{origin}: {exc}")
            return []

        events = []
        for timestamp, fields in steps:
            fields = self._derive(fields)
            if fields is None:
                continue
            events.append(
                Event(
                    timestamp=timestamp,
                    source=SOURCE,
                    host=fields.get("app") or fields.get("host") or None,
                    fields=fields,
                    raw=text,
                    origin=origin,
                )
            )
        if len(events) > 1:  # several steps from one line: tell them apart
            events = [_renumber(event, index) for index, event in enumerate(events, start=1)]
        return events

    def _derive(self, values: dict[str, Any]) -> dict[str, Any] | None:
        """Flatten a step into event fields and add the derived ones (``None``: skip it)."""
        fields: dict[str, str | tuple[str, ...]] = {}
        for key, value in values.items():
            if key.startswith("_"):
                continue
            flat = _arguments(value) if key == "arguments" else _flatten(value)
            if flat not in ("", ()):
                fields[key] = flat
        kind = fields["type"]
        session = str(fields.get("session_id") or fields.get("actor") or "")
        content = fields.get("content", "")

        if kind == "system":
            known = self._prompts.get(session)
            # Chat Completions requests repeat the system prompt in every call.
            if values.get("_repeated") and known is not None and known.text == _normalize(content):
                return None
            self._remember(self._prompts, session, _SystemPrompt(content), MAX_SESSIONS)
        elif kind == "response" and (prompt := self._prompts.get(session)) is not None:
            overlap = prompt.overlap(content)
            if overlap >= prompt.threshold:
                fields["system_prompt_echo"] = "true"
                fields["system_prompt_overlap"] = str(overlap)

        if kind == "tool_call":
            _add_urls(fields, "url", _urls(values.get("arguments")))
        elif kind == "response":
            _add_urls(fields, "image_url", _images(content))
        if content:
            if hidden := hidden_text(content):
                fields["hidden_text"] = hidden
            found = _personal_values(content)
            if kind == "prompt" and found:
                given = self._given.get(session, frozenset())
                self._remember(self._given, session, given | {v for _, v in found}, MAX_SESSIONS)
            elif kind == "response":
                given = self._given.get(session, frozenset())
                found = [(pii, value) for pii, value in found if value not in given]
            if found:
                fields["pii"] = tuple(dict.fromkeys(pii for pii, _ in found))
        return fields

    def _mcp_steps(self, record: dict[str, Any]) -> list[tuple[datetime, dict[str, Any]]]:
        message = record["message"] if isinstance(record.get("message"), dict) else record
        common = {
            "session_id": _first(record, _SESSION_KEYS),
            "actor": _first(record, _ACTOR_KEYS),
            "server": record.get("server"),
            "app": record.get("app"),
        }
        timestamp = _timestamp(record.get("timestamp"))
        call_key = (
            f"{common['server'] or ''}/{common['session_id'] or ''}",
            str(message.get("id")),
        )

        if message.get("method") == "tools/call":
            params = message.get("params") if isinstance(message.get("params"), dict) else {}
            tool = str(params.get("name") or "")
            if "id" in message:
                self._remember(self._calls, call_key, tool, MAX_PENDING_CALLS)
            step = {"type": "tool_call", "tool": tool, "arguments": params.get("arguments")}
            return [(timestamp, {**step, "call_id": message.get("id"), **common})]
        if "method" in message or ("result" not in message and "error" not in message):
            return []  # other requests and notifications
        tool = self._calls.pop(call_key, None)
        if tool is None:
            result = message.get("result")
            if isinstance(result, dict) and isinstance(result.get("tools"), list):
                # The answer to tools/list, recognized by its shape: the request
                # may not have been logged.
                return [
                    (timestamp, {**_tool_definition(definition), **common})
                    for definition in result["tools"]
                    if isinstance(definition, dict)
                ]
            return []  # the answer to initialize, prompts/list...
        step = {"type": "tool_result", "tool": tool, "call_id": message.get("id")}
        if isinstance(message.get("error"), dict):
            step |= {"is_error": True, "content": message["error"].get("message")}
        elif isinstance(message.get("result"), dict):
            result = message["result"]
            parts = [_text(result.get("content"))]
            if result.get("structuredContent") is not None:
                parts.append(json.dumps(result["structuredContent"], ensure_ascii=False))
            step |= {
                "is_error": bool(result.get("isError")),
                "content": "\n".join(filter(None, parts)),
            }
        return [(timestamp, {**step, **common})]

    @staticmethod
    def _remember(memory: OrderedDict[Any, Any], key: Any, value: Any, limit: int) -> None:
        memory[key] = value
        memory.move_to_end(key)
        while len(memory) > limit:
            memory.popitem(last=False)


def parse(path: str | Path) -> ParseResult:
    """Parse an agent log file (``.jsonl``, ``.json`` or ``.ndjson``)."""
    path = Path(path)
    result = ParseResult()
    reader = Reader()
    with path.open(encoding="utf-8", errors="replace") as handle:
        for lineno, raw in enumerate(handle, start=1):
            origin = f"{path.name}:{lineno}"
            result.events.extend(reader.read_line(raw, origin=origin, warnings=result.warnings))
    return result


def dialect_of(record: dict[str, Any]) -> str | None:
    """The shape of a record: ``vigie``, ``openai``, ``mcp``, or ``None`` for none of them."""
    if str(record.get("type")) in EVENT_TYPES:
        return "vigie"
    request, response = record.get("request"), record.get("response")
    if (
        (isinstance(request, dict) and isinstance(request.get("messages"), list))
        or (isinstance(response, dict) and _completion(response) is not None)
        or record.get("object") == "chat.completion"
    ):
        return "openai"
    message = record.get("message") if isinstance(record.get("message"), dict) else record
    if message.get("jsonrpc") == "2.0":
        return "mcp"
    return None


def hidden_text(text: str) -> str:
    """The text hidden in Unicode tag characters, decoded to ASCII ("" if there is none)."""
    runs = _TAG_RUN.findall(_TAG_FLAG.sub("", text))
    return " ".join("".join(chr(ord(char) - 0xE0000) for char in run) for run in runs)


def personal_data(text: str) -> tuple[str, ...]:
    """The kinds of checksum-valid personal data in ``text``: ``payment_card``, ``iban``."""
    return tuple(dict.fromkeys(kind for kind, _ in _personal_values(text)))


def _personal_values(text: str) -> list[tuple[str, str]]:
    """Each card number and IBAN in ``text`` that passes its checks, as (kind, value)."""
    found = []
    for match in _CARD.finditer(text):
        digits = re.sub(r"\D", "", match[0])
        if _card_range(digits) and _luhn(digits) and digits not in EXAMPLE_NUMBERS:
            found.append(("payment_card", digits))
    for match in _IBAN.finditer(text):
        iban = match[0].replace(" ", "")
        if 15 <= len(iban) <= 34 and _mod97(iban) and iban not in EXAMPLE_NUMBERS:
            found.append(("iban", iban))
    return found


class _SystemPrompt:
    """A system prompt, indexed to find the runs of it a response reproduces."""

    def __init__(self, text: str) -> None:
        self.text = _normalize(text)
        self.threshold = min(ECHO_MIN, max(ECHO_WINDOW, len(self.text) // 2))
        # Every window of ECHO_WINDOW characters that starts a word of the prompt.
        self._windows: dict[str, int] = {}
        for start in _word_starts(self.text):
            window = self.text[start : start + ECHO_WINDOW]
            if len(window) == ECHO_WINDOW:
                self._windows.setdefault(window, start)

    def overlap(self, response: str) -> int:
        """How many characters of the prompt the response reproduces in long enough runs."""
        text = _normalize(response)
        starts = sorted(
            self._windows[window]
            for start in _word_starts(text)
            if (window := text[start : start + ECHO_WINDOW]) in self._windows
        )
        covered, end = 0, -1
        for start in starts:  # length of the union of [start, start + ECHO_WINDOW)
            covered += ECHO_WINDOW - max(0, end - start)
            end = max(end, start + ECHO_WINDOW)
        return covered


def _vigie_step(record: dict[str, Any]) -> tuple[datetime, dict[str, Any]]:
    fields = {key: value for key, value in record.items() if key != "timestamp"}
    actor = _first(record, _ACTOR_KEYS)
    for key in _ACTOR_KEYS[1:]:
        fields.pop(key, None)
    fields["actor"] = actor
    fields["content"] = _text(record.get("content"))
    return _timestamp(record.get("timestamp")), fields


def _openai_steps(record: dict[str, Any]) -> list[tuple[datetime, dict[str, Any]]]:
    request = record.get("request") if isinstance(record.get("request"), dict) else {}
    response = _completion(record.get("response")) or _completion(record) or {}
    metadata = request.get("metadata") if isinstance(request.get("metadata"), dict) else {}
    common = {
        "session_id": _first(record, _SESSION_KEYS) or _first(metadata, _SESSION_KEYS),
        "actor": _first(record, _ACTOR_KEYS)
        or _first(request, _ACTOR_KEYS)
        or _first(metadata, _ACTOR_KEYS),
        "model": response.get("model") or request.get("model"),
        "app": record.get("app"),
        "src_ip": record.get("src_ip"),
    }
    timestamp = _timestamp(record.get("timestamp") or response.get("created"))

    steps: list[dict[str, Any]] = []
    messages = [m for m in request.get("messages") or [] if isinstance(m, dict)]
    system = [m for m in messages if m.get("role") in ("system", "developer")]
    if system:
        steps.append(
            {"type": "system", "content": _text(system[-1].get("content")), "_repeated": 1}
        )
    # The request repeats the whole conversation: only what follows the model's
    # last answer is new.
    answered = [i for i, m in enumerate(messages) if m.get("role") == "assistant"]
    tools = {
        call.get("id"): (call.get("function") or {}).get("name")
        for m in messages
        for call in m.get("tool_calls") or []
        if isinstance(call, dict)
    }
    for message in messages[answered[-1] + 1 if answered else 0 :]:
        role, content = message.get("role"), _text(message.get("content"))
        if role == "user":
            steps.append({"type": "prompt", "content": content})
        elif role in ("tool", "function"):
            tool = tools.get(message.get("tool_call_id")) or message.get("name")
            steps.append({"type": "tool_result", "tool": tool, "content": content})

    usage = response.get("usage") if isinstance(response.get("usage"), dict) else {}
    tokens = {"tokens_in": usage.get("prompt_tokens"), "tokens_out": usage.get("completion_tokens")}
    for choice in response.get("choices") or []:
        message = choice.get("message") if isinstance(choice, dict) else None
        if not isinstance(message, dict):
            continue
        content = _text(message.get("content")) or _text(message.get("refusal"))
        if content:
            steps.append({"type": "response", "content": content, **tokens})
            tokens = {}
        calls = list(message.get("tool_calls") or [])
        if isinstance(message.get("function_call"), dict):  # the API's older form
            calls.append({"function": message["function_call"]})
        for call in calls:
            function = call.get("function") or {}
            steps.append(
                {
                    "type": "tool_call",
                    "tool": function.get("name"),
                    "arguments": function.get("arguments"),
                    "call_id": call.get("id"),
                }
            )
    return [(timestamp, {**step, **common}) for step in steps]


def _tool_definition(definition: dict[str, Any]) -> dict[str, Any]:
    """A tool of an MCP ``tools/list`` answer, as a ``tool_definition`` step."""
    descriptions = [definition.get("description")]
    descriptions += _schema_descriptions(definition.get("inputSchema"))
    return {
        "type": "tool_definition",
        "tool": definition.get("name"),
        "content": "\n".join(text for text in descriptions if isinstance(text, str) and text),
    }


def _schema_descriptions(schema: Any, depth: int = 0) -> list[Any]:
    """The descriptions of the parameters in a JSON Schema, nested ones included."""
    if not isinstance(schema, dict) or depth > MAX_SCHEMA_DEPTH:
        return []
    found = []
    properties = schema.get("properties")
    for value in properties.values() if isinstance(properties, dict) else ():
        if isinstance(value, dict):
            found.append(value.get("description"))
            found += _schema_descriptions(value, depth + 1)
    found += _schema_descriptions(schema.get("items"), depth + 1)
    return found


def _completion(value: Any) -> dict[str, Any] | None:
    """A Chat Completions response body, also when wrapped as in the Batch API output."""
    if not isinstance(value, dict):
        return None
    if isinstance(value.get("body"), dict):
        value = value["body"]
    if value.get("object") == "chat.completion" or isinstance(value.get("choices"), list):
        return value
    return None


def _timestamp(value: Any) -> datetime:
    if isinstance(value, str) and value.strip():
        # A timestamp without an offset is UTC, as in most JSON exports.
        return parse_iso8601(value, default_tz=UTC)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        seconds = value / 1000 if value > 1e11 else value  # milliseconds since 1970
        try:
            return datetime.fromtimestamp(seconds, UTC)
        except (OverflowError, OSError, ValueError) as exc:
            raise ValueError(f"invalid Unix timestamp: {value!r}") from exc
    raise ValueError("no timestamp")


def _first(record: dict[str, Any], keys: tuple[str, ...]) -> Any:
    return next((record[key] for key in keys if record.get(key) not in (None, "")), None)


def _text(value: Any) -> str:
    """Text of a message content: a string, or the text parts of a list of content parts."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts = []
        for part in value:
            if isinstance(part, str):
                parts.append(part)
            elif isinstance(part, dict):
                text = part.get("text")
                if isinstance(part.get("resource"), dict):  # MCP embedded resource
                    text = part["resource"].get("text")
                if isinstance(text, str):
                    parts.append(text)
        return "\n".join(parts)
    return json.dumps(value, ensure_ascii=False)


def _flatten(value: Any) -> str:
    """A field value as rules compare it: text, true/false, or compact JSON for structures."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def _arguments(value: Any) -> str:
    """Tool arguments as one canonical JSON text, whether they came as an object or a string."""
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            return value  # not JSON: a raw command line, for example
        if isinstance(decoded, (dict, list)):
            return _flatten(decoded)
        return value
    return _flatten(value)


def _strings(value: Any) -> Iterator[str]:
    """Every string inside a value, however deeply nested (JSON strings are decoded)."""
    if isinstance(value, str):
        stripped = value.strip()
        if stripped[:1] in "{[" and stripped[-1:] in "}]":
            try:
                yield from _strings(json.loads(stripped))
                return
            except json.JSONDecodeError:
                pass
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def _urls(arguments: Any) -> Iterator[str]:
    for text in _strings(arguments):
        for match in _URL.finditer(text):
            yield match[0].rstrip(_URL_END)


def _images(content: str) -> Iterator[str]:
    for pattern in (_MARKDOWN_IMAGE, _HTML_IMAGE):
        for match in pattern.finditer(content):
            yield match[1]


def _add_urls(fields: dict[str, Any], name: str, urls: Iterator[str]) -> None:
    """Set ``name`` to the distinct URLs, and ``<prefix>_host`` to their host names."""
    found = list(dict.fromkeys(urls))
    hosts = [host for url in found if (host := _host(url))]
    if found:
        fields[name] = tuple(found)
    if hosts:
        fields[name.removesuffix("_url") + "_host"] = tuple(dict.fromkeys(hosts))


def _host(url: str) -> str | None:
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def _renumber(event: Event, index: int) -> Event:
    return Event(
        timestamp=event.timestamp,
        source=event.source,
        host=event.host,
        fields=event.fields,
        raw=event.raw,
        origin=f"{event.origin}#{index}",
    )


def _normalize(text: str) -> str:
    return " ".join(text.split()).casefold()


def _word_starts(text: str) -> Iterator[int]:
    yield 0
    for match in re.finditer(" ", text):
        yield match.end()


def _card_range(digits: str) -> bool:
    return any(prefix.match(digits) and len(digits) in lengths for prefix, lengths in _CARD_RANGES)


def _luhn(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        digit = int(char)
        if index % 2:
            digit = digit * 2 - 9 if digit > 4 else digit * 2
        total += digit
    return total % 10 == 0 and len(set(digits)) > 1


def _mod97(iban: str) -> bool:
    rearranged = iban[4:] + iban[:4]
    return int("".join(str(int(char, 36)) for char in rearranged)) % 97 == 1
