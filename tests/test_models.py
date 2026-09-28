import dataclasses
from datetime import datetime, timedelta, timezone

import pytest

from vigie.models import LEVELS, Alert, Event, RuleMeta
from vigie.timeutils import UTC

TS = datetime(2024, 6, 1, 12, 0, tzinfo=UTC)


def test_minimal_event():
    event = Event(timestamp=TS, source="auth")
    assert event.event_id is None
    assert event.host is None
    assert dict(event.fields) == {}
    assert event.raw == ""


def test_timestamp_is_normalized_to_utc():
    local = datetime(2024, 6, 1, 14, 0, tzinfo=timezone(timedelta(hours=2)))
    event = Event(timestamp=local, source="auth")
    assert event.timestamp == TS
    assert event.timestamp.utcoffset() == timedelta(0)


def test_naive_timestamp_is_rejected():
    with pytest.raises(ValueError, match="naive"):
        Event(timestamp=datetime(2024, 6, 1, 12, 0), source="auth")


def test_source_is_lowercased():
    assert Event(timestamp=TS, source="Security").source == "security"


def test_empty_source_is_rejected():
    with pytest.raises(ValueError, match="source"):
        Event(timestamp=TS, source="")


def test_event_is_immutable():
    event = Event(timestamp=TS, source="auth")
    with pytest.raises(dataclasses.FrozenInstanceError):
        event.source = "sysmon"  # type: ignore[misc]


def test_fields_are_read_only_and_copied():
    original = {"User": "alice"}
    event = Event(timestamp=TS, source="security", fields=original)
    original["User"] = "mallory"
    assert event.get("User") == "alice"
    with pytest.raises(TypeError):
        event.fields["User"] = "mallory"  # type: ignore[index]


def test_get_with_default():
    event = Event(timestamp=TS, source="sysmon", event_id=1, fields={"Image": "C:\\x.exe"})
    assert event.get("Image") == "C:\\x.exe"
    assert event.get("CommandLine") is None
    assert event.get("CommandLine", "") == ""


class TestRuleMetaAndAlert:
    def test_severity_order(self):
        ranks = [RuleMeta(id="r", title="t", level=level).severity for level in LEVELS]
        assert ranks == [0, 1, 2, 3, 4]

    def test_unknown_level(self):
        with pytest.raises(ValueError, match="unknown level"):
            RuleMeta(id="r", title="t", level="severe")

    def test_alert_sorts_events_and_freezes_group(self):
        late = Event(timestamp=TS + timedelta(minutes=5), source="auth")
        early = Event(timestamp=TS, source="auth")
        group = {"src_ip": "192.0.2.1"}
        alert = Alert(RuleMeta(id="r", title="t", level="low"), (late, early), group)
        assert alert.events == (early, late)
        assert alert.timestamp == TS
        assert alert.last_seen == TS + timedelta(minutes=5)
        group["src_ip"] = "changed"
        assert alert.group["src_ip"] == "192.0.2.1"
        with pytest.raises(TypeError):
            alert.group["src_ip"] = "x"  # type: ignore[index]

    def test_alert_needs_events(self):
        with pytest.raises(ValueError, match="at least one event"):
            Alert(RuleMeta(id="r", title="t", level="low"), ())
