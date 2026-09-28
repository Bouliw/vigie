import textwrap
from datetime import datetime, timedelta

import pytest
import yaml

from vigie.models import Event
from vigie.timeutils import UTC

T0 = datetime(2024, 3, 10, 9, 0, tzinfo=UTC)


@pytest.fixture
def rule_doc():
    """Parse an indented YAML snippet written inline in a test."""

    def parse(text):
        return yaml.safe_load(textwrap.dedent(text))

    return parse


@pytest.fixture
def write_rules(tmp_path):
    """Write YAML snippets to files in a temporary rules folder and return the folder."""

    def write(**files):
        for name, text in files.items():
            path = tmp_path / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(textwrap.dedent(text), encoding="utf-8")
        return tmp_path

    return write


@pytest.fixture
def make_event():
    """Build an Event ``seconds`` after a fixed reference time."""

    def make(source="auth", seconds=0, event_id=None, raw="", **fields):
        return Event(
            timestamp=T0 + timedelta(seconds=seconds),
            source=source,
            event_id=event_id,
            fields=fields,
            raw=raw,
            origin=f"test:{seconds}",
        )

    return make
