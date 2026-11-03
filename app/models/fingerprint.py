"""Deterministic event deduplication fingerprint generator for WinSentinel."""

from __future__ import annotations

import hashlib


def compute_event_fingerprint(
    computer: str,
    provider: str,
    channel: str,
    record_id: int | None,
    raw_payload: str,
) -> str:
    """Compute a deterministic SHA-256 fingerprint for event deduplication (D-04).

    Format:
        SHA256(computer | provider | channel | record_id | raw_payload)

    Handles None record_id by converting to empty string, and encodes with
    errors='replace' to guard against unhandled Unicode surrogate crashes.
    """
    rec_str = str(record_id) if record_id is not None else ""
    key = f"{computer}|{provider}|{channel}|{rec_str}|{raw_payload}"
    return hashlib.sha256(key.encode("utf-8", errors="replace")).hexdigest()
