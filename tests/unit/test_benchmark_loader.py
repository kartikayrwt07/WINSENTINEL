"""Unit tests for the benchmark dataset loader and JSONL datasets."""

from pathlib import Path
import pytest

from app.evaluation.loader import load_benchmark_dataset, save_benchmark_dataset
from app.models.evaluation import BenchmarkEvent


def test_load_attack_dataset():
    path = Path("tests/data/benchmarks/attacks.jsonl")
    events = load_benchmark_dataset(path)

    assert len(events) >= 16
    for b_event in events:
        assert b_event.label.is_malicious is True
        assert len(b_event.label.expected_rules) >= 1
        assert b_event.event.provider == "Microsoft-Windows-Sysmon"

    # Verify that all 16 Sysmon rules are present in expected_rules
    all_expected = {r for e in events for r in e.label.expected_rules}
    for rule_num in range(1, 17):
        rule_id = f"WS-SYS-{rule_num:03d}"
        assert rule_id in all_expected, f"Missing rule {rule_id} in attack dataset"


def test_load_benign_noise_dataset():
    path = Path("tests/data/benchmarks/benign_admin_noise.jsonl")
    events = load_benchmark_dataset(path)

    assert len(events) >= 16
    for b_event in events:
        assert b_event.label.is_malicious is False
        assert len(b_event.label.expected_rules) == 0


def test_load_nonexistent_dataset():
    with pytest.raises(FileNotFoundError):
        load_benchmark_dataset("tests/data/benchmarks/non_existent.jsonl")


def test_load_corrupt_json(tmp_path: Path):
    corrupt_file = tmp_path / "corrupt.jsonl"
    corrupt_file.write_text("{\"not\": \"valid json", encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid JSON on line 1"):
        load_benchmark_dataset(corrupt_file)


def test_load_invalid_schema(tmp_path: Path):
    invalid_file = tmp_path / "invalid.jsonl"
    invalid_file.write_text("{\"event\": {}, \"label\": {}}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Schema validation error on line 1"):
        load_benchmark_dataset(invalid_file)


def test_save_and_reload_dataset(tmp_path: Path):
    original_path = Path("tests/data/benchmarks/attacks.jsonl")
    events = load_benchmark_dataset(original_path)

    temp_path = tmp_path / "saved_attacks.jsonl"
    save_benchmark_dataset(temp_path, events)

    reloaded = load_benchmark_dataset(temp_path)
    assert len(reloaded) == len(events)
    assert reloaded[0].label.expected_rules == events[0].label.expected_rules
