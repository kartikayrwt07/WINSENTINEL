from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

import Evtx.Evtx as evtx
from app.ingestion.base import RawRecord
from app.ingestion.evtx_parser import EVTXParser
from app.models.stats import ImportStatistics


def test_evtx_stream_valid_records(tmp_path: Path):
    evtx_path = tmp_path / "valid.evtx"
    evtx_path.write_bytes(b"dummy evtx data")

    # Mock python-evtx Evtx context manager and records
    mock_record1 = MagicMock()
    mock_record1.record_num.return_value = 101
    mock_record1.xml.return_value = "<Event><System><EventRecordID>101</EventRecordID></System></Event>"

    mock_record2 = MagicMock()
    mock_record2.record_num.return_value = 102
    mock_record2.xml.return_value = "<Event><System><EventRecordID>102</EventRecordID></System></Event>"

    mock_chunk = MagicMock()
    mock_chunk.records.return_value = iter([mock_record1, mock_record2])

    mock_evtx_instance = MagicMock()
    mock_evtx_instance.chunks.return_value = iter([mock_chunk])
    mock_evtx_instance.__enter__.return_value = mock_evtx_instance
    mock_evtx_instance.__exit__.return_value = None

    parser = EVTXParser()
    stats = ImportStatistics()

    with patch("Evtx.Evtx.Evtx", return_value=mock_evtx_instance):
        records = list(parser.stream_records(evtx_path, stats=stats))

    assert len(records) == 2
    assert records[0].record_id == 101
    assert "<EventRecordID>101</EventRecordID>" in records[0].raw_payload
    assert records[0].format == "evtx"
    assert records[1].record_id == 102
    assert records[1].format == "evtx"
    assert stats.total_events == 2
    assert stats.malformed_events == 0


def test_evtx_stream_recovers_from_corrupt_records(tmp_path: Path):
    evtx_path = tmp_path / "corrupt.evtx"
    evtx_path.write_bytes(b"dummy evtx data")

    mock_valid_record1 = MagicMock()
    mock_valid_record1.record_num.return_value = 1
    mock_valid_record1.xml.return_value = "<Event><System><EventRecordID>1</EventRecordID></System></Event>"

    mock_corrupt_record = MagicMock()
    mock_corrupt_record.record_num.return_value = 2
    mock_corrupt_record.xml.side_effect = evtx.InvalidRecordException()

    mock_valid_record2 = MagicMock()
    mock_valid_record2.record_num.return_value = 3
    mock_valid_record2.xml.return_value = "<Event><System><EventRecordID>3</EventRecordID></System></Event>"

    mock_chunk = MagicMock()
    mock_chunk.records.return_value = iter([mock_valid_record1, mock_corrupt_record, mock_valid_record2])

    mock_evtx_instance = MagicMock()
    mock_evtx_instance.chunks.return_value = iter([mock_chunk])
    mock_evtx_instance.__enter__.return_value = mock_evtx_instance
    mock_evtx_instance.__exit__.return_value = None

    parser = EVTXParser()
    stats = ImportStatistics()

    with patch("Evtx.Evtx.Evtx", return_value=mock_evtx_instance):
        records = list(parser.stream_records(evtx_path, stats=stats))

    assert len(records) == 3
    assert records[0].record_id == 1
    assert records[0].metadata.get("is_corrupt") is not True

    # Second record is corrupted but recovered
    assert records[1].metadata.get("is_corrupt") is True
    assert "Invalid" in records[1].metadata["error"] or "Parse" in records[1].metadata["error"]

    # Third record parsed successfully
    assert records[2].record_id == 3
    assert stats.malformed_events == 1
    assert stats.total_events == 3


def test_evtx_stream_handles_unicode_decode_error(tmp_path: Path):
    evtx_path = tmp_path / "unicode_err.evtx"
    evtx_path.write_bytes(b"dummy")

    mock_rec = MagicMock()
    mock_rec.record_num.return_value = 99
    mock_rec.xml.side_effect = UnicodeDecodeError("utf-8", b"\xff\xff", 0, 1, "invalid start byte")

    mock_chunk = MagicMock()
    mock_chunk.records.return_value = iter([mock_rec])

    mock_evtx_instance = MagicMock()
    mock_evtx_instance.chunks.return_value = iter([mock_chunk])
    mock_evtx_instance.__enter__.return_value = mock_evtx_instance
    mock_evtx_instance.__exit__.return_value = None

    parser = EVTXParser()
    stats = ImportStatistics()

    with patch("Evtx.Evtx.Evtx", return_value=mock_evtx_instance):
        records = list(parser.stream_records(evtx_path, stats=stats))

    assert len(records) == 1
    assert records[0].metadata.get("is_corrupt") is True
    assert stats.malformed_events == 1


def test_evtx_chunk_error_continues_to_next_chunk(tmp_path: Path):
    evtx_path = tmp_path / "chunk_err.evtx"
    evtx_path.write_bytes(b"dummy")

    # Chunk 1 raises ParseException when enumerating records
    mock_chunk1 = MagicMock()
    mock_chunk1.records.side_effect = evtx.ParseException("Bad chunk header")

    # Chunk 2 has valid records
    mock_rec2 = MagicMock()
    mock_rec2.record_num.return_value = 200
    mock_rec2.xml.return_value = "<Event><System><EventRecordID>200</EventRecordID></System></Event>"

    mock_chunk2 = MagicMock()
    mock_chunk2.records.return_value = iter([mock_rec2])

    mock_evtx_instance = MagicMock()
    mock_evtx_instance.chunks.return_value = iter([mock_chunk1, mock_chunk2])
    mock_evtx_instance.__enter__.return_value = mock_evtx_instance
    mock_evtx_instance.__exit__.return_value = None

    parser = EVTXParser()
    stats = ImportStatistics()

    with patch("Evtx.Evtx.Evtx", return_value=mock_evtx_instance):
        records = list(parser.stream_records(evtx_path, stats=stats))

    # We should get a corrupt record from chunk 1 failure, and a valid record from chunk 2
    assert len(records) == 2
    assert records[0].metadata.get("is_corrupt") is True
    assert records[1].record_id == 200
    assert stats.malformed_events == 1
    assert stats.total_events == 2


def test_evtx_stream_is_generator(tmp_path: Path):
    import inspect

    evtx_path = tmp_path / "stream.evtx"
    evtx_path.write_bytes(b"dummy")

    parser = EVTXParser()
    gen = parser.stream_records(evtx_path)
    assert inspect.isgenerator(gen)
    gen.close()

