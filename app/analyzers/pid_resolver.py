"""Temporal PID lifespan resolution and binary search interval indexing."""

from __future__ import annotations

import bisect
import logging
from datetime import datetime, timezone
from typing import NamedTuple

from app.analyzers.process_analyzer import ProcessNode

logger = logging.getLogger(__name__)


class ProcessLifespan(NamedTuple):
    """Temporal interval bounding a specific process execution instance."""

    start_time: datetime
    end_time: datetime | None
    node: ProcessNode


class TemporalPIDResolver:
    """Indexes process lifespans by (computer, PID) to disambiguate recycled PIDs over time.

    Windows aggressively recycles integer PIDs once processes terminate.
    This resolver indexes [start_time, end_time] intervals and executes O(log k)
    binary search (bisect) queries to locate the active process at any query timestamp.
    """

    def __init__(self) -> None:
        # Key: (computer.lower().strip(), pid) -> list of ProcessLifespan sorted by start_time
        self._index: dict[tuple[str, int], list[ProcessLifespan]] = {}

    def _normalize_key(self, computer: str, pid: int) -> tuple[str, int]:
        return computer.strip().lower(), pid

    def _ensure_utc(self, dt: datetime) -> datetime:
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    def register_process_creation(self, node: ProcessNode) -> None:
        """Register a new process creation and cap any prior unterminated instance on collision."""
        key = self._normalize_key(node.computer, node.process_id)
        lifespans = self._index.setdefault(key, [])

        start_utc = self._ensure_utc(node.start_time)
        end_utc = self._ensure_utc(node.end_time) if node.end_time is not None else None

        # Check if previous instance was unterminated or overlaps, and cap it at new start_time
        if lifespans:
            last = lifespans[-1]
            if last.end_time is None or last.end_time > start_utc:
                capped_node = last.node.model_copy(update={"end_time": start_utc})
                lifespans[-1] = ProcessLifespan(
                    start_time=last.start_time,
                    end_time=start_utc,
                    node=capped_node,
                )

        lifespans.append(
            ProcessLifespan(
                start_time=start_utc,
                end_time=end_utc,
                node=node,
            )
        )
        lifespans.sort(key=lambda item: item.start_time)

    # Alias for method name in plan
    add_process = register_process_creation

    def register_process_termination(
        self,
        computer: str,
        pid: int,
        termination_time: datetime,
        process_guid: str | None = None,
    ) -> ProcessNode | None:
        """Update termination timestamp on active matching process lifespan."""
        key = self._normalize_key(computer, pid)
        lifespans = self._index.get(key)
        if not lifespans:
            return None

        term_utc = self._ensure_utc(termination_time)

        # If process_guid is known, match exact node
        if process_guid:
            for idx in reversed(range(len(lifespans))):
                item = lifespans[idx]
                if item.node.process_guid == process_guid:
                    updated_node = item.node.model_copy(update={"end_time": term_utc})
                    lifespans[idx] = ProcessLifespan(
                        start_time=item.start_time,
                        end_time=term_utc,
                        node=updated_node,
                    )
                    return updated_node

        # Otherwise match the most recent active lifespan where start_time <= term_utc
        for idx in reversed(range(len(lifespans))):
            item = lifespans[idx]
            if item.start_time <= term_utc and (item.end_time is None or item.end_time >= term_utc):
                updated_node = item.node.model_copy(update={"end_time": term_utc})
                lifespans[idx] = ProcessLifespan(
                    start_time=item.start_time,
                    end_time=term_utc,
                    node=updated_node,
                )
                return updated_node

        return None

    # Alias for method name in plan
    terminate_process = register_process_termination

    def resolve(
        self,
        computer: str,
        pid: int,
        timestamp: datetime,
    ) -> ProcessNode | None:
        """Locate the exact process instance active on computer with PID at timestamp.

        Evaluates start_time <= timestamp <= (end_time or infinity).
        Complexity: O(log k) using binary search.
        """
        key = self._normalize_key(computer, pid)
        lifespans = self._index.get(key)
        if not lifespans:
            return None

        query_utc = self._ensure_utc(timestamp)

        # Binary search for rightmost lifespan with start_time <= query_utc
        starts = [item.start_time for item in lifespans]
        idx = bisect.bisect_right(starts, query_utc) - 1

        if idx >= 0:
            candidate = lifespans[idx]
            if candidate.start_time <= query_utc:
                if candidate.end_time is None or candidate.end_time >= query_utc:
                    return candidate.node

        return None

    # Alias for method name in plan
    resolve_process_at_time = resolve
