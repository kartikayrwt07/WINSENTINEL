"""Unit tests for SHA-256 event fingerprinting and ImportStatistics auditing."""

from datetime import datetime, timezone
import pytest

from app.models.fingerprint import compute_event_fingerprint
from app.models.stats import ImportStatistics, QuarantineRecord


class TestComputeEventFingerprint:
    def test_deterministic_output(self):
        """Test that identical inputs produce identical 64-character hex digests."""
        fp1 = compute_event_fingerprint(
            computer="WORKSTATION01",
            provider="Microsoft-Windows-Sysmon",
            channel="Microsoft-Windows-Sysmon/Operational",
            record_id=1024,
            raw_payload="<Event>TestPayload1</Event>",
        )
        fp2 = compute_event_fingerprint(
            computer="WORKSTATION01",
            provider="Microsoft-Windows-Sysmon",
            channel="Microsoft-Windows-Sysmon/Operational",
            record_id=1024,
            raw_payload="<Event>TestPayload1</Event>",
        )
        assert len(fp1) == 64
        assert fp1 == fp2

    def test_handles_none_record_id(self):
        """Test that record_id=None is handled without raising TypeError."""
        fp = compute_event_fingerprint(
            computer="SERVER02",
            provider="Microsoft-Windows-Security-Auditing",
            channel="Security",
            record_id=None,
            raw_payload="<Event>NoRecordId</Event>",
        )
        assert isinstance(fp, str)
        assert len(fp) == 64

    def test_resilience_to_record_id_rollover(self):
        """Test that distinct raw_payloads produce distinct digests even with identical record_id."""
        fp1 = compute_event_fingerprint(
            computer="SERVER01",
            provider="Microsoft-Windows-Sysmon",
            channel="Microsoft-Windows-Sysmon/Operational",
            record_id=1,
            raw_payload="<Event><ProcessId>100</ProcessId></Event>",
        )
        fp2 = compute_event_fingerprint(
            computer="SERVER01",
            provider="Microsoft-Windows-Sysmon",
            channel="Microsoft-Windows-Sysmon/Operational",
            record_id=1,
            raw_payload="<Event><ProcessId>999</ProcessId></Event>",
        )
        assert fp1 != fp2

    def test_unicode_surrogate_safety(self):
        """Test that strings containing irregular characters are encoded without unhandled errors."""
        surrogate_string = "Payload with special chars: \u2620 \U0001F6E1 \uFFFD"
        fp = compute_event_fingerprint(
            computer="DC01",
            provider="Security",
            channel="Security",
            record_id=50,
            raw_payload=surrogate_string,
        )
        assert isinstance(fp, str)
        assert len(fp) == 64


class TestImportStatistics:
    def test_initial_state(self):
        """Test default values of ImportStatistics."""
        stats = ImportStatistics(file_path="C:\\logs\\sysmon.evtx")
        assert stats.file_path == "C:\\logs\\sysmon.evtx"
        assert stats.total_events == 0
        assert stats.total_records == 0
        assert stats.parsed_events == 0
        assert stats.malformed_events == 0
        assert stats.quarantined_events == 0
        assert stats.duplicate_events == 0
        assert stats.error_log == []
        assert stats.errors == []
        assert stats.quarantined_records == []
        assert stats.end_time is None
        assert isinstance(stats.start_time, datetime)

    def test_record_parsed_increment(self):
        """Test recording parsed events increments total and parsed counters."""
        stats = ImportStatistics()
        stats.record_parsed()
        stats.record_parsed()
        assert stats.total_events == 2
        assert stats.parsed_events == 2

    def test_record_malformed_increment(self):
        """Test recording malformed event records diagnostic message."""
        stats = ImportStatistics()
        stats.record_malformed("Corrupted XML chunk at offset 0x400")
        assert stats.total_events == 1
        assert stats.malformed_events == 1
        assert stats.error_log == ["Corrupted XML chunk at offset 0x400"]
        assert stats.errors == ["Corrupted XML chunk at offset 0x400"]

    def test_record_quarantined(self):
        """Test recording quarantined record retains QuarantineRecord instance."""
        stats = ImportStatistics()
        q_rec = QuarantineRecord(
            event_id=1,
            record_id=105,
            raw_payload="<CorruptEvent />",
            error_reasons=["Unparseable timestamp", "Missing Image path"],
            file_path="test.evtx",
        )
        stats.record_quarantined(q_rec)
        assert stats.total_events == 1
        assert stats.quarantined_events == 1
        assert len(stats.quarantined_records) == 1
        assert stats.quarantined_records[0].record_id == 105
        assert stats.quarantined_records[0].error_reasons == ["Unparseable timestamp", "Missing Image path"]

    def test_record_duplicate(self):
        """Test recording duplicate increments duplicate counter."""
        stats = ImportStatistics()
        stats.record_duplicate()
        assert stats.total_events == 1
        assert stats.duplicate_events == 1

    def test_finish_sets_end_time(self):
        """Test finish() sets UTC end_time."""
        stats = ImportStatistics()
        assert stats.end_time is None
        stats.finish()
        assert stats.end_time is not None
        assert stats.end_time.tzinfo == timezone.utc

    def test_constructor_aliases(self):
        """Test passing total_records and errors in constructor aliases."""
        stats = ImportStatistics(total_records=10, errors=["err1", "err2"])
        assert stats.total_events == 10
        assert stats.total_records == 10
        assert stats.error_log == ["err1", "err2"]
        assert stats.errors == ["err1", "err2"]
