import os
from pathlib import Path
import pytest

from app.utils.security import (
    sanitize_input_path,
    DEFAULT_ALLOWED_EXTENSIONS,
    DEFAULT_MAX_SIZES,
)


def test_sanitize_valid_path(tmp_path: Path):
    evtx_file = tmp_path / "valid.evtx"
    evtx_file.write_bytes(b"dummy evtx content")

    resolved = sanitize_input_path(evtx_file, base_dir=tmp_path)
    assert resolved == evtx_file.resolve()
    assert resolved.exists()


def test_sanitize_file_not_found(tmp_path: Path):
    missing_file = tmp_path / "nonexistent.evtx"
    with pytest.raises(FileNotFoundError, match="does not exist"):
        sanitize_input_path(missing_file)


def test_sanitize_path_traversal(tmp_path: Path):
    base_dir = tmp_path / "sandbox"
    base_dir.mkdir()
    outside_file = tmp_path / "outside.evtx"
    outside_file.write_bytes(b"outside")

    # Try traversal using relative path with '..'
    traversal_path = base_dir / ".." / "outside.evtx"
    with pytest.raises(PermissionError, match="Path traversal attempt detected"):
        sanitize_input_path(traversal_path, base_dir=base_dir)


def test_sanitize_disallowed_extension(tmp_path: Path):
    bad_file = tmp_path / "payload.exe"
    bad_file.write_bytes(b"MZ...")
    with pytest.raises(ValueError, match="Unsupported file extension"):
        sanitize_input_path(bad_file)


def test_sanitize_custom_allowed_extensions(tmp_path: Path):
    xml_file = tmp_path / "events.xml"
    xml_file.write_text("<Events/>", encoding="utf-8")

    # If we restrict allowed to only .evtx, .xml should fail
    with pytest.raises(ValueError, match="Unsupported file extension"):
        sanitize_input_path(xml_file, allowed_extensions=[".evtx"])

    # If we allow .xml, it succeeds
    res = sanitize_input_path(xml_file, allowed_extensions=[".xml"])
    assert res == xml_file.resolve()


def test_sanitize_file_size_exceeded_custom(tmp_path: Path):
    large_file = tmp_path / "events.json"
    large_file.write_bytes(b"X" * 1024)

    # Limit to 500 bytes
    with pytest.raises(ValueError, match="File size .* exceeds maximum allowed"):
        sanitize_input_path(large_file, max_size_bytes=500)


def test_sanitize_file_size_exceeded_default(tmp_path: Path, monkeypatch):
    jsonl_file = tmp_path / "events.jsonl"
    jsonl_file.write_bytes(b"X" * 100)

    # Monkeypatch default max size for .jsonl to 50 bytes
    monkeypatch.setitem(DEFAULT_MAX_SIZES, ".jsonl", 50)
    with pytest.raises(ValueError, match="File size .* exceeds maximum allowed"):
        sanitize_input_path(jsonl_file)


def test_sanitize_accepts_all_supported_extensions(tmp_path: Path):
    for ext in DEFAULT_ALLOWED_EXTENSIONS:
        f = tmp_path / f"test{ext}"
        f.write_text("{}", encoding="utf-8")
        res = sanitize_input_path(f)
        assert res.suffix.lower() == ext
