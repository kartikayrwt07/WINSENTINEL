"""Unit tests for NormalizedEvent schema, timestamp parsing, and hash utilities."""

from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from app.models.events import (
    EventCategory,
    NormalizedEvent,
    parse_hashes_string,
    parse_sysmon_hashes,
    parse_windows_timestamp,
)


class TestNormalizedEvent:
    def test_instantiate_valid_event(self, sample_valid_event_dict: dict):
        """Test successful instantiation of NormalizedEvent with all valid fields."""
        event = NormalizedEvent(**sample_valid_event_dict)
        assert event.event_id == 1
        assert event.record_id == 4201
        assert event.provider == "Microsoft-Windows-Sysmon"
        assert event.channel == "Microsoft-Windows-Sysmon/Operational"
        assert event.computer == "WIN-SENTINEL-DEV"
        assert event.event_category == EventCategory.PROCESS
        assert event.event_type == "process_create"
        assert event.process_id == 4128
        assert event.user == "CORP\\jdoe"
        assert event.hashes["sha256"] == "b89d73c8b7a58e8d552309c1e14f4462615456201b4b6f71a6dbb3673f921b59"
        assert event.raw_payload == sample_valid_event_dict["raw_payload"]
        assert event.is_quarantined is False
        assert event.quarantine_reasons == []

    def test_immutability_frozen_model(self, sample_valid_event_dict: dict):
        """Test that NormalizedEvent is frozen and raises ValidationError on attribute mutation."""
        event = NormalizedEvent(**sample_valid_event_dict)
        with pytest.raises(ValidationError):
            event.process_id = 9999  # type: ignore[misc]

        with pytest.raises(ValidationError):
            event.image = "malicious.exe"  # type: ignore[misc]

    def test_raw_payload_preserved_verbatim(self, sample_valid_event_dict: dict):
        """Test that raw_payload is preserved verbatim without alteration (D-02, NORM-08)."""
        raw_string = " <RandomUnparsedXml with whitespace and <Tags> & symbols! \n\t "
        payload_dict = dict(sample_valid_event_dict)
        payload_dict["raw_payload"] = raw_string
        event = NormalizedEvent(**payload_dict)
        assert event.raw_payload == raw_string

    def test_extra_fields_storage(self, sample_valid_event_dict: dict):
        """Test that arbitrary unmapped attributes are safely stored in extra_fields dictionary."""
        payload_dict = dict(sample_valid_event_dict)
        payload_dict["extra_fields"] = {
            "CustomTag": "SecurityCanary",
            "NestedData": {"flag": True, "code": 123},
        }
        event = NormalizedEvent(**payload_dict)
        assert event.extra_fields["CustomTag"] == "SecurityCanary"
        assert event.extra_fields["NestedData"]["code"] == 123

    def test_extra_forbid_enforcement(self, sample_valid_event_dict: dict):
        """Test that extra unmapped top-level attributes are rejected under extra='forbid'."""
        payload_dict = dict(sample_valid_event_dict)
        payload_dict["unknown_top_level_field"] = "unexpected_data"
        with pytest.raises(ValidationError) as excinfo:
            NormalizedEvent(**payload_dict)
        assert "Extra inputs are not permitted" in str(excinfo.value)

    def test_automatic_coercion_of_timestamp_string(self, sample_valid_event_dict: dict):
        """Test that passing an ISO-8601 string to timestamp field automatically parses into UTC datetime."""
        payload_dict = dict(sample_valid_event_dict)
        payload_dict["timestamp"] = "2023-04-10T14:22:15.1234567Z"
        event = NormalizedEvent(**payload_dict)
        assert isinstance(event.timestamp, datetime)
        assert event.timestamp.tzinfo == timezone.utc
        assert event.timestamp.year == 2023
        assert event.timestamp.microsecond == 123456

    def test_automatic_coercion_of_hashes_string(self, sample_valid_event_dict: dict):
        """Test that passing a Sysmon Hashes string automatically parses into lowercase dict."""
        payload_dict = dict(sample_valid_event_dict)
        payload_dict["hashes"] = "SHA256=ABCDEF1234,MD5=5678FEDCBA"
        event = NormalizedEvent(**payload_dict)
        assert event.hashes == {"sha256": "ABCDEF1234", "md5": "5678FEDCBA"}


class TestTimestampParsing:
    def test_parse_iso8601_with_nanoseconds(self):
        """Test parsing Windows ISO-8601 timestamps with 7 subsecond digits and trailing Z."""
        raw = "2023-04-10T14:22:15.1234567Z"
        dt = parse_windows_timestamp(raw)
        assert dt == datetime(2023, 4, 10, 14, 22, 15, 123456, tzinfo=timezone.utc)
        assert dt.tzinfo == timezone.utc

    def test_parse_sysmon_space_delimited(self):
        """Test parsing Sysmon UtcTime space-delimited timestamps without explicit timezone."""
        raw = "2023-04-10 14:22:15.120"
        dt = parse_windows_timestamp(raw)
        assert dt == datetime(2023, 4, 10, 14, 22, 15, 120000, tzinfo=timezone.utc)
        assert dt.tzinfo == timezone.utc

    def test_parse_unix_epoch_integers(self):
        """Test parsing Unix epoch timestamps in both seconds and milliseconds."""
        # Seconds
        epoch_sec = 1681136535
        dt_sec = parse_windows_timestamp(epoch_sec)
        assert dt_sec == datetime(2023, 4, 10, 14, 22, 15, tzinfo=timezone.utc)

        # Milliseconds
        epoch_ms = 1681136535123
        dt_ms = parse_windows_timestamp(epoch_ms)
        assert dt_ms == datetime(2023, 4, 10, 14, 22, 15, 123000, tzinfo=timezone.utc)

    def test_parse_numeric_strings(self):
        """Test parsing epoch timestamps provided as string digits."""
        dt = parse_windows_timestamp("1681136535")
        assert dt == datetime(2023, 4, 10, 14, 22, 15, tzinfo=timezone.utc)

    def test_parse_datetime_object(self):
        """Test passing an existing datetime object (both naive and aware)."""
        naive_dt = datetime(2023, 4, 10, 14, 22, 15)
        parsed = parse_windows_timestamp(naive_dt)
        assert parsed.tzinfo == timezone.utc
        assert parsed.hour == 14

    def test_invalid_timestamp_raises_value_error(self):
        """Test that unparseable timestamp raises ValueError when fallback_on_error is False."""
        with pytest.raises(ValueError):
            parse_windows_timestamp("not-a-valid-timestamp")

        with pytest.raises(ValueError):
            parse_windows_timestamp(None)

    def test_invalid_timestamp_with_fallback(self):
        """Test that unparseable timestamp returns current UTC datetime when fallback_on_error is True."""
        dt = parse_windows_timestamp("corrupted-timestamp", fallback_on_error=True)
        assert isinstance(dt, datetime)
        assert dt.tzinfo == timezone.utc


class TestHashParsing:
    def test_parse_sysmon_hashes_standard(self):
        """Test parsing comma-separated Sysmon Hashes string."""
        raw = "SHA256=B89D73C8B7A58E8D,MD5=A6C11690040D9B0A,IMPHASH=20743B8FE"
        res = parse_sysmon_hashes(raw)
        assert res == {
            "sha256": "B89D73C8B7A58E8D",
            "md5": "A6C11690040D9B0A",
            "imphash": "20743B8FE",
        }

    def test_parse_sysmon_hashes_spaces_and_commas(self):
        """Test parsing with mixed space and comma delimiters."""
        raw = "SHA256=11223344, MD5=55667788 IMPHASH=9900AABB"
        res = parse_sysmon_hashes(raw)
        assert res["sha256"] == "11223344"
        assert res["md5"] == "55667788"
        assert res["imphash"] == "9900AABB"

    def test_parse_hashes_string_alias(self):
        """Test that parse_hashes_string alias behaves identically."""
        raw = "MD5=ABCDEF"
        assert parse_hashes_string(raw) == {"md5": "ABCDEF"}

    def test_parse_empty_or_none_hashes(self):
        """Test handling of None, empty string, or invalid types."""
        assert parse_sysmon_hashes(None) == {}
        assert parse_sysmon_hashes("") == {}
        assert parse_sysmon_hashes(123) == {}  # type: ignore[arg-type]
