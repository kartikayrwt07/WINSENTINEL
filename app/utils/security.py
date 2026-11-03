"""Security utilities for input validation, path sanitization, and quota enforcement."""

from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path

# Default allowed extensions for forensic event logs
DEFAULT_ALLOWED_EXTENSIONS: frozenset[str] = frozenset({
    ".evtx",
    ".xml",
    ".json",
    ".jsonl",
})

# Default file size limits: 2GB for EVTX binary logs, 500MB for text formats
DEFAULT_MAX_SIZES: dict[str, int] = {
    ".evtx": 2 * 1024 * 1024 * 1024,
    ".xml": 500 * 1024 * 1024,
    ".json": 500 * 1024 * 1024,
    ".jsonl": 500 * 1024 * 1024,
}


def sanitize_input_path(
    user_path: str | Path,
    base_dir: str | Path | None = None,
    allowed_extensions: Iterable[str] | None = None,
    max_size_bytes: int | None = None,
) -> Path:
    """Validate and sanitize an input file path.

    Enforces:
    1. File existence (raises FileNotFoundError).
    2. Regular file check (raises ValueError).
    3. Path traversal prevention when base_dir is provided (raises PermissionError).
    4. Allowed extension validation (raises ValueError).
    5. File size quota enforcement (raises ValueError).

    Args:
        user_path: Path supplied by caller (string or Path object).
        base_dir: Optional boundary directory for path traversal protection.
        allowed_extensions: Optional set/list of allowed extensions (including dot).
            Defaults to DEFAULT_ALLOWED_EXTENSIONS.
        max_size_bytes: Optional byte limit. Defaults to DEFAULT_MAX_SIZES per extension.

    Returns:
        Resolved and validated absolute Path object.
    """
    resolved_path = Path(user_path).resolve()

    if not resolved_path.exists():
        raise FileNotFoundError(f"File does not exist: {resolved_path}")

    if not resolved_path.is_file():
        raise ValueError(f"Path is not a regular file: {resolved_path}")

    if base_dir is not None:
        resolved_base = Path(base_dir).resolve()
        try:
            resolved_path.relative_to(resolved_base)
        except ValueError:
            raise PermissionError(
                f"Path traversal attempt detected: {resolved_path} is outside base directory {resolved_base}"
            )

    ext = resolved_path.suffix.lower()
    allowed = {e.lower() for e in allowed_extensions} if allowed_extensions is not None else DEFAULT_ALLOWED_EXTENSIONS

    if ext not in allowed:
        raise ValueError(
            f"Unsupported file extension '{ext}'. Allowed extensions: {sorted(allowed)}"
        )

    file_size = resolved_path.stat().st_size
    limit = max_size_bytes if max_size_bytes is not None else DEFAULT_MAX_SIZES.get(ext)

    if limit is not None and file_size > limit:
        raise ValueError(
            f"File size ({file_size} bytes) exceeds maximum allowed ({limit} bytes) for '{resolved_path.name}'"
        )

    return resolved_path
