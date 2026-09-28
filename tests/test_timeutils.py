from datetime import datetime, timedelta, timezone

import pytest

from vigie.timeutils import UTC, ensure_utc, parse_iso8601

UTC_PLUS_2 = timezone(timedelta(hours=2))


class TestEnsureUtc:
    def test_converts_offset_to_utc(self):
        local = datetime(2024, 6, 1, 14, 0, tzinfo=UTC_PLUS_2)
        result = ensure_utc(local)
        assert result == datetime(2024, 6, 1, 12, 0, tzinfo=UTC)
        assert result.utcoffset() == timedelta(0)

    def test_rejects_naive_datetime(self):
        with pytest.raises(ValueError, match="naive"):
            ensure_utc(datetime(2024, 6, 1, 12, 0))


class TestParseIso8601:
    def test_trailing_z(self):
        expected = datetime(2019, 3, 19, 23, 34, 25, tzinfo=UTC)
        assert parse_iso8601("2019-03-19T23:34:25Z") == expected

    def test_seven_digit_fraction_is_truncated(self):
        # EVTX SystemTime format.
        result = parse_iso8601("2019-03-19T23:34:25.3754345Z")
        assert result.microsecond == 375434

    def test_short_fraction_is_padded(self):
        assert parse_iso8601("2024-01-01T00:00:00.5+00:00").microsecond == 500000

    def test_offset_is_converted(self):
        result = parse_iso8601("2024-06-01T14:00:00+02:00")
        assert result == datetime(2024, 6, 1, 12, 0, tzinfo=UTC)

    def test_space_separator(self):
        assert parse_iso8601("2024-06-01 12:00:00Z") == datetime(2024, 6, 1, 12, 0, tzinfo=UTC)

    def test_naive_uses_default_tz(self):
        result = parse_iso8601("2024-06-01T14:00:00", default_tz=UTC_PLUS_2)
        assert result == datetime(2024, 6, 1, 12, 0, tzinfo=UTC)

    def test_naive_without_default_is_rejected(self):
        with pytest.raises(ValueError, match="no timezone"):
            parse_iso8601("2024-06-01T14:00:00")

    @pytest.mark.parametrize("text", ["", "yesterday", "2024-13-01T00:00:00Z"])
    def test_invalid_input(self, text):
        with pytest.raises(ValueError):
            parse_iso8601(text)
