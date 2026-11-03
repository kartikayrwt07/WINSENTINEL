import json
from pathlib import Path
import pytest

from app.ingestion.base import RawRecord
from app.ingestion.json_parser import JSONParser
from app.models.stats import ImportStatistics


def test_json_parser_jsonl_valid(tmp_path: Path):
    file_path = tmp_path / "valid.jsonl"
    lines = [
        json.dumps({"EventRecordID": 501, "EventID": 1, "Image": "cmd.exe"}),
        json.dumps({"EventRecordID": 502, "EventID": 3, "DestinationIp": "1.1.1.1"}),
    ]
    file_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    parser = JSONParser()
    stats = ImportStatistics()
    records = list(parser.stream_records(file_path, stats=stats))

    assert len(records) == 2
    assert records[0].record_id == 501
    assert records[0].format == "jsonl"
    assert records[0].metadata["parsed_json"]["Image"] == "cmd.exe"
    assert records[1].record_id == 502
    assert stats.total_events == 2
    assert stats.malformed_events == 0


def test_json_parser_jsonl_corrupt_line_recovery(tmp_path: Path):
    file_path = tmp_path / "corrupt_lines.jsonl"
    content = (
        '{"EventRecordID": 10, "msg": "ok"}\n'
        'NOT_VALID_JSON{{{\n'
        '{"EventRecordID": 11, "msg": "also ok"}\n'
    )
    file_path.write_text(content, encoding="utf-8")

    parser = JSONParser()
    stats = ImportStatistics()
    records = list(parser.stream_records(file_path, stats=stats))

    assert len(records) == 3
    assert records[0].record_id == 10
    assert records[0].metadata.get("is_corrupt") is not True

    # Corrupt line
    assert records[1].record_id is None
    assert records[1].metadata.get("is_corrupt") is True
    assert "NOT_VALID_JSON" in records[1].raw_payload

    # Recovered line
    assert records[2].record_id == 11
    assert records[2].metadata["parsed_json"]["msg"] == "also ok"
    assert stats.total_events == 3
    assert stats.malformed_events == 1


def test_json_parser_json_array_valid(tmp_path: Path):
    file_path = tmp_path / "array.json"
    data = [
        {"record_id": 201, "event_name": "proc_start"},
        {"System": {"EventRecordID": 202}, "event_name": "net_conn"},
    ]
    file_path.write_text(json.dumps(data), encoding="utf-8")

    parser = JSONParser()
    stats = ImportStatistics()
    records = list(parser.stream_records(file_path, stats=stats))

    assert len(records) == 2
    assert records[0].record_id == 201
    assert records[0].format == "json"
    assert records[1].record_id == 202
    assert records[1].format == "json"
    assert stats.total_events == 2
    assert stats.malformed_events == 0


def test_json_parser_json_array_malformed(tmp_path: Path):
    file_path = tmp_path / "corrupt_array.json"
    file_path.write_text("[{'unclosed': true, ", encoding="utf-8")

    parser = JSONParser()
    stats = ImportStatistics()
    records = list(parser.stream_records(file_path, stats=stats))

    assert len(records) == 1
    assert records[0].metadata.get("is_corrupt") is True
    assert stats.malformed_events == 1
