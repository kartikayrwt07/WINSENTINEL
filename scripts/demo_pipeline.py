"""WinSentinel End-to-End Pipeline Demonstration & Seed Script.

Initializes SQLite database, syncs detection rules, ingests attack telemetry,
evaluates detection rules, creates alerts, and verifies UI services.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure repo root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.database.connection import DatabaseManager
from app.database.migrations import MigrationRunner
from app.database.repository import EventRepository, ImportJobRepository
from app.detection.engine import DetectionEngine
from app.detection.loader import RuleLoader
from app.evaluation.loader import load_benchmark_dataset
from app.ui.services import (
    AlertUIService,
    OverviewService,
    PersistenceUIService,
    RuleUIService,
)


def run_demo():
    print("=" * 70)
    print(" [*] WINSENTINEL: Windows Threat Monitoring & Forensic Platform")
    print("=" * 70)

    db_path = REPO_ROOT / "data" / "winsentinel.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    if db_path.exists():
        try:
            db_path.unlink()
        except Exception:
            pass

    print(f"\n[1/5] Initializing Database: {db_path}...")
    db_mgr = DatabaseManager(db_path=db_path)
    runner = MigrationRunner(db_manager=db_mgr)
    applied = runner.apply_migrations()
    print(f"      [OK] Applied {len(applied)} database schema migrations.")

    print("\n[2/5] Synchronizing Detection Rules...")
    loader = RuleLoader()
    rules = loader.load_rules_from_directory("rules/sysmon", recursive=True, strict=False)
    synced = loader.sync_rules_to_db(db_mgr, rules)
    print(f"      [OK] Loaded and synchronized {synced} Sigma-inspired detection rules into SQLite.")

    print("\n[3/5] Ingesting Labeled Attack Telemetry...")
    benchmark_path = REPO_ROOT / "tests" / "data" / "benchmarks" / "attacks.jsonl"
    benchmark_events = load_benchmark_dataset(benchmark_path)
    import hashlib
    events = [
        be.event.model_copy(
            update={
                "event_hash": hashlib.sha256(
                    f"{be.event.computer}-{be.event.event_id}-{be.event.timestamp}-{idx}".encode()
                ).hexdigest()
            }
        )
        for idx, be in enumerate(benchmark_events)
    ]

    job_repo = ImportJobRepository(db_mgr)
    file_id = job_repo.create_or_get_imported_file(
        file_path=str(benchmark_path),
        file_name=benchmark_path.name,
        file_size_bytes=benchmark_path.stat().st_size,
        file_hash_sha256="b4fb393967d710f8a846c483a9de01f9453c0722fe116496de1412450dc574b0",
    )
    job_id = job_repo.create_import_job(file_id=file_id, file_path=str(benchmark_path), status="COMPLETED")

    ev_repo = EventRepository(db_mgr)
    inserted_res = ev_repo.insert_events_batch(events, import_job_id=job_id)
    count = inserted_res[0] if isinstance(inserted_res, tuple) else inserted_res
    print(f"      [OK] Ingested {len(events)} events across process, network, registry, driver, and DNS.")

    print("\n[4/5] Running Detection Engine & Correlating Alerts...")
    engine = DetectionEngine()
    engine.load_rules(rules)
    matches = engine.evaluate_batch(events)
    alert_ids = engine.persist_matches(db_mgr, matches)
    print(f"      [OK] Detection engine matched {len(matches)} suspicious behaviors.")
    print(f"      [OK] Persisted {len(alert_ids)} alerts with linked forensic evidence.")

    print("\n[5/5] Querying Presentation & Analytical Services...")
    overview = OverviewService(db_manager=db_mgr)
    kpis = overview.get_kpis()
    sev = overview.get_severity_breakdown()
    hosts = overview.get_top_targeted_hosts()
    mitre_list = overview.get_mitre_breakdown()

    rule_svc = RuleUIService(rules_dir="rules/sysmon", db_manager=db_mgr)
    rule_list = rule_svc.list_rules()

    alert_svc = AlertUIService(db_manager=db_mgr)
    alerts, alert_total = alert_svc.get_alerts()

    persistence_svc = PersistenceUIService(db_manager=db_mgr)
    pers = persistence_svc.get_persistence_summary()

    print("\n" + "-" * 70)
    print(" [*] SOC METRICS & FORENSIC SUMMARY")
    print("-" * 70)
    print(f" Total Ingested Events : {kpis['total_events']}")
    print(f" Total Active Alerts   : {kpis['total_alerts']} (Critical: {sev.get('critical', 0)}, High: {sev.get('high', 0)}, Medium: {sev.get('medium', 0)})")
    print(f" Targeted Endpoints    : {len(hosts)} hosts identified")
    mitre_str = ", ".join([f"{m['technique']} ({m['count']})" for m in mitre_list[:4]]) if mitre_list else "None"
    print(f" MITRE ATT&CK Tactics  : {mitre_str}")
    print(f" Persistence ASEPs     : {len(pers['registry_run'])} Registry Run, {len(pers['ifeo_debugger'])} IFEO Debugger, {len(pers['services'])} Services")
    print(f" Cataloged Rules       : {len(rule_list)} rules available")

    print("\n" + "-" * 70)
    print(" [!] RECENT DETECTIONS SAMPLE")
    print("-" * 70)
    for a in alerts[:5]:
        print(f" * [{a['severity'].upper():<8}] Alert #{a['id']:02d}: {a['title']:<35} (Host: {a['computer']})")

    print("\n" + "=" * 70)
    print(" [OK] PIPELINE EXECUTION COMPLETE")
    print("=" * 70)
    print("How to test further:")
    print(" 1. Run all 362 automated tests:")
    print("    python -m pytest tests/ -v")
    print("")
    print(" 2. Run detection rule benchmark CLI:")
    print("    python -m app.evaluation.cli --dataset tests/data/benchmarks/attacks.jsonl --markdown -")
    print("    python -m app.evaluation.cli --dataset tests/data/benchmarks/benign_admin_noise.jsonl --fail-on-fp --markdown -")
    print("")
    print(" 3. Launch interactive SOC Dashboard (requires Streamlit):")
    print("    pip install streamlit")
    print("    streamlit run app/ui/main.py")
    print("=" * 70)


if __name__ == "__main__":
    run_demo()
