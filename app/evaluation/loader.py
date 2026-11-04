"""Benchmark dataset loader and serializer for WinSentinel."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import ValidationError

from app.models.evaluation import BenchmarkEvent


def load_benchmark_dataset(file_path: Path | str) -> list[BenchmarkEvent]:
    """Load and validate a JSONL benchmark dataset into a list of BenchmarkEvent instances.

    Args:
        file_path: Path to the JSONL dataset file.

    Returns:
        List of validated BenchmarkEvent objects.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If a line contains invalid JSON or fails BenchmarkEvent validation.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Benchmark dataset file not found: {path}")

    events: list[BenchmarkEvent] = []
    with path.open("r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            try:
                data = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON on line {line_num} in '{path}': {exc}"
                ) from exc

            try:
                b_event = BenchmarkEvent.model_validate(data)
                events.append(b_event)
            except ValidationError as exc:
                raise ValueError(
                    f"Schema validation error on line {line_num} in '{path}': {exc}"
                ) from exc

    return events


def save_benchmark_dataset(file_path: Path | str, events: list[BenchmarkEvent]) -> None:
    """Serialize a list of BenchmarkEvent instances to a JSONL file.

    Args:
        file_path: Target path to write JSONL data.
        events: List of BenchmarkEvent objects.
    """
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as f:
        for event in events:
            f.write(event.model_dump_json() + "\n")

