"""Unit tests for TemporalPIDResolver and PID recycling disambiguation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.analyzers.pid_resolver import ProcessLifespan, TemporalPIDResolver
from app.analyzers.process_analyzer import ProcessNode


def test_register_process_creation_and_basic_resolve() -> None:
    """Verify registration and resolution of single process lifespan."""
    resolver = TemporalPIDResolver()
    t0 = datetime(2026, 11, 4, 10, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 11, 4, 10, 30, 0, tzinfo=timezone.utc)

    node = ProcessNode(
        process_guid="{guid-1}",
        process_id=4096,
        computer="WORKSTATION01",
        image=r"C:\Windows\System32\svchost.exe",
        start_time=t0,
    )

    resolver.register_process_creation(node)

    # Query before start_time -> None
    assert resolver.resolve("WORKSTATION01", 4096, t0 - timedelta(seconds=1)) is None

    # Query at start_time -> returns node
    assert resolver.resolve("WORKSTATION01", 4096, t0) == node

    # Query later while active (unterminated) -> returns node
    assert resolver.resolve("WORKSTATION01", 4096, t1) == node

    # Query differing host -> None
    assert resolver.resolve("SERVER01", 4096, t1) is None

    # Query differing PID -> None
    assert resolver.resolve("WORKSTATION01", 9999, t1) is None


def test_pid_recycling_disambiguation() -> None:
    """Verify two distinct processes reusing the same PID at different times are isolated."""
    resolver = TemporalPIDResolver()
    t0 = datetime(2026, 11, 4, 8, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 11, 4, 8, 30, 0, tzinfo=timezone.utc)  # proc1 terminates
    t2 = datetime(2026, 11, 4, 9, 0, 0, tzinfo=timezone.utc)  # proc2 created
    t3 = datetime(2026, 11, 4, 9, 45, 0, tzinfo=timezone.utc)  # proc2 terminates

    proc1 = ProcessNode(
        process_guid="{proc-1}",
        process_id=4096,
        computer="WORKSTATION01",
        image=r"C:\Windows\System32\svchost.exe",
        start_time=t0,
        end_time=t1,
    )

    proc2 = ProcessNode(
        process_guid="{proc-2}",
        process_id=4096,
        computer="WORKSTATION01",
        image=r"C:\Windows\System32\powershell.exe",
        start_time=t2,
        end_time=t3,
    )

    resolver.register_process_creation(proc1)
    resolver.register_process_creation(proc2)

    # During proc1 lifespan
    resolved_p1 = resolver.resolve("WORKSTATION01", 4096, datetime(2026, 11, 4, 8, 15, 0, tzinfo=timezone.utc))
    assert resolved_p1 is not None
    assert resolved_p1.process_guid == "{proc-1}"
    assert resolved_p1.image == r"C:\Windows\System32\svchost.exe"

    # In the gap between proc1 termination and proc2 creation -> None
    gap_time = datetime(2026, 11, 4, 8, 45, 0, tzinfo=timezone.utc)
    assert resolver.resolve("WORKSTATION01", 4096, gap_time) is None

    # During proc2 lifespan
    resolved_p2 = resolver.resolve("WORKSTATION01", 4096, datetime(2026, 11, 4, 9, 15, 0, tzinfo=timezone.utc))
    assert resolved_p2 is not None
    assert resolved_p2.process_guid == "{proc-2}"
    assert resolved_p2.image == r"C:\Windows\System32\powershell.exe"

    # After proc2 termination -> None
    assert resolver.resolve("WORKSTATION01", 4096, datetime(2026, 11, 4, 10, 0, 0, tzinfo=timezone.utc)) is None


def test_collision_capping_unterminated_process() -> None:
    """Verify that a new creation on same PID caps an earlier unterminated process lifespan."""
    resolver = TemporalPIDResolver()
    t0 = datetime(2026, 11, 4, 10, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 11, 4, 11, 0, 0, tzinfo=timezone.utc)

    # Proc 1 has no end_time
    proc1 = ProcessNode(
        process_guid="{proc-1}",
        process_id=5000,
        computer="HOST01",
        image="app1.exe",
        start_time=t0,
        end_time=None,
    )

    # Proc 2 created at t1 with same PID
    proc2 = ProcessNode(
        process_guid="{proc-2}",
        process_id=5000,
        computer="HOST01",
        image="app2.exe",
        start_time=t1,
        end_time=None,
    )

    resolver.register_process_creation(proc1)
    resolver.register_process_creation(proc2)

    # Proc 1 should now be capped at t1
    at_10_30 = datetime(2026, 11, 4, 10, 30, 0, tzinfo=timezone.utc)
    assert resolver.resolve("HOST01", 5000, at_10_30) == proc1.model_copy(update={"end_time": t1})

    # At t1, proc2 is active
    assert resolver.resolve("HOST01", 5000, t1) == proc2


def test_register_process_termination_by_guid_and_by_pid() -> None:
    """Verify termination registration by explicit GUID and by matching active PID."""
    resolver = TemporalPIDResolver()
    t0 = datetime(2026, 11, 4, 10, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 11, 4, 10, 30, 0, tzinfo=timezone.utc)

    node = ProcessNode(
        process_guid="{term-guid}",
        process_id=6000,
        computer="HOST01",
        image="worker.exe",
        start_time=t0,
    )
    resolver.register_process_creation(node)

    # Terminate by process_guid
    updated = resolver.register_process_termination("HOST01", 6000, t1, process_guid="{term-guid}")
    assert updated is not None
    assert updated.end_time == t1

    # After termination -> None
    assert resolver.resolve("HOST01", 6000, t1 + timedelta(seconds=1)) is None

    # At termination time -> returns node
    assert resolver.resolve("HOST01", 6000, t1) is not None

    # Terminate without process_guid on fresh process
    node2 = ProcessNode(
        process_guid="{term-guid-2}",
        process_id=7000,
        computer="HOST01",
        image="worker2.exe",
        start_time=t0,
    )
    resolver.register_process_creation(node2)
    updated2 = resolver.register_process_termination("HOST01", 7000, t1)
    assert updated2 is not None
    assert updated2.end_time == t1

    # Terminate non-existent -> returns None
    assert resolver.register_process_termination("HOST01", 9999, t1) is None


def test_binary_search_efficiency_many_recycled_pids() -> None:
    """Verify bisect resolution accurately handles a long chain of 50 recycled PIDs."""
    resolver = TemporalPIDResolver()
    base_time = datetime(2026, 11, 4, 0, 0, 0, tzinfo=timezone.utc)

    # Create 50 processes sharing PID 8000, each living for 10 minutes with 5 min gap
    nodes = []
    for i in range(50):
        start = base_time + timedelta(minutes=i * 15)
        end = start + timedelta(minutes=10)
        n = ProcessNode(
            process_guid=f"{{proc-{i:03d}}}",
            process_id=8000,
            computer="BUSY-HOST",
            image=f"worker_{i}.exe",
            start_time=start,
            end_time=end,
        )
        nodes.append(n)
        resolver.register_process_creation(n)

    # Test random sampling of points
    for i in [0, 10, 25, 49]:
        query_active = base_time + timedelta(minutes=i * 15 + 5)
        resolved = resolver.resolve("BUSY-HOST", 8000, query_active)
        assert resolved is not None
        assert resolved.process_guid == f"{{proc-{i:03d}}}"

        # Gap between i and i+1
        query_gap = base_time + timedelta(minutes=i * 15 + 12)
        assert resolver.resolve("BUSY-HOST", 8000, query_gap) is None


def test_method_aliases() -> None:
    """Verify add_process, terminate_process, resolve_process_at_time aliases."""
    resolver = TemporalPIDResolver()
    t0 = datetime(2026, 11, 4, 10, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 11, 4, 10, 10, 0, tzinfo=timezone.utc)

    node = ProcessNode(
        process_guid="{alias-guid}",
        process_id=9000,
        computer="HOST01",
        image="test.exe",
        start_time=t0,
    )
    resolver.add_process(node)
    assert resolver.resolve_process_at_time("HOST01", 9000, t0) == node

    resolver.terminate_process("HOST01", 9000, t1)
    assert resolver.resolve_process_at_time("HOST01", 9000, t1 + timedelta(seconds=1)) is None
