-- 001_initial_schema.sql
-- WinSentinel Initial Relational Schema DDL
-- Establishes 12 core tables and forensic query optimization indexes.

-- 1. Schema Migrations
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TEXT NOT NULL,
    checksum TEXT NOT NULL
);

-- 2. Imported Files
CREATE TABLE IF NOT EXISTS imported_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_path TEXT NOT NULL,
    file_name TEXT NOT NULL,
    file_size_bytes INTEGER NOT NULL,
    file_hash_sha256 TEXT NOT NULL UNIQUE,
    first_imported_at TEXT NOT NULL,
    last_imported_at TEXT NOT NULL
);

-- 3. Import Jobs
CREATE TABLE IF NOT EXISTS import_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER REFERENCES imported_files(id) ON DELETE SET NULL,
    file_path TEXT NOT NULL,
    status TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT,
    total_events INTEGER NOT NULL DEFAULT 0,
    parsed_events INTEGER NOT NULL DEFAULT 0,
    malformed_events INTEGER NOT NULL DEFAULT 0,
    quarantined_events INTEGER NOT NULL DEFAULT 0,
    duplicate_events INTEGER NOT NULL DEFAULT 0,
    error_log_json TEXT
);

-- 4. Normalized Events
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    import_job_id INTEGER REFERENCES import_jobs(id) ON DELETE SET NULL,
    event_id INTEGER NOT NULL,
    record_id INTEGER,
    provider TEXT NOT NULL,
    channel TEXT NOT NULL,
    computer TEXT NOT NULL,
    timestamp_utc TEXT NOT NULL,
    event_category TEXT NOT NULL,
    event_type TEXT NOT NULL,
    process_guid TEXT,
    process_id INTEGER,
    image TEXT,
    command_line TEXT,
    current_directory TEXT,
    user TEXT,
    logon_guid TEXT,
    logon_id TEXT,
    integrity_level TEXT,
    hashes_json TEXT,
    parent_process_guid TEXT,
    parent_process_id INTEGER,
    parent_image TEXT,
    parent_command_line TEXT,
    parent_user TEXT,
    target_process_guid TEXT,
    target_process_id INTEGER,
    target_image TEXT,
    granted_access TEXT,
    call_trace TEXT,
    source_ip TEXT,
    source_port INTEGER,
    source_hostname TEXT,
    destination_ip TEXT,
    destination_port INTEGER,
    destination_hostname TEXT,
    protocol TEXT,
    query_name TEXT,
    query_status TEXT,
    query_results TEXT,
    target_filename TEXT,
    image_loaded TEXT,
    signed TEXT,
    signature TEXT,
    signature_status TEXT,
    registry_event_type TEXT,
    registry_target_object TEXT,
    registry_details TEXT,
    registry_new_name TEXT,
    wmi_operation TEXT,
    wmi_consumer TEXT,
    wmi_filter TEXT,
    wmi_query TEXT,
    service_name TEXT,
    service_file_name TEXT,
    task_name TEXT,
    task_content TEXT,
    script_block_text TEXT,
    script_block_id TEXT,
    script_path TEXT,
    extra_fields_json TEXT,
    raw_payload TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE,
    is_quarantined INTEGER NOT NULL DEFAULT 0,
    quarantine_reasons_json TEXT
);

-- 5. Processes
CREATE TABLE IF NOT EXISTS processes (
    process_guid TEXT PRIMARY KEY,
    process_id INTEGER NOT NULL,
    image TEXT NOT NULL,
    command_line TEXT,
    current_directory TEXT,
    user TEXT,
    integrity_level TEXT,
    parent_process_guid TEXT REFERENCES processes(process_guid) ON DELETE SET NULL,
    parent_process_id INTEGER,
    parent_image TEXT,
    parent_command_line TEXT,
    start_time TEXT NOT NULL,
    end_time TEXT,
    exit_code INTEGER,
    is_orphaned INTEGER NOT NULL DEFAULT 0,
    is_anomalous INTEGER NOT NULL DEFAULT 0,
    anomaly_reasons_json TEXT
);

-- 6. Detection Rules
CREATE TABLE IF NOT EXISTS detection_rules (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    author TEXT,
    rule_yaml TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- 7. Alerts
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT REFERENCES detection_rules(id) ON DELETE SET NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'New',
    description TEXT,
    computer TEXT NOT NULL,
    user TEXT,
    process_guid TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    event_count INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    mitre_tactics_json TEXT,
    mitre_techniques_json TEXT
);

-- 8. Alert Evidence
CREATE TABLE IF NOT EXISTS alert_evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    matched_field TEXT,
    matched_value TEXT,
    explanation TEXT,
    UNIQUE(alert_id, event_id)
);

-- 9. Investigations
CREATE TABLE IF NOT EXISTS investigations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Open',
    priority TEXT NOT NULL DEFAULT 'Medium',
    lead_analyst TEXT,
    summary TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    closed_at TEXT
);

-- 10. Analyst Notes
CREATE TABLE IF NOT EXISTS analyst_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER REFERENCES alerts(id) ON DELETE CASCADE,
    investigation_id INTEGER REFERENCES investigations(id) ON DELETE CASCADE,
    author TEXT NOT NULL,
    note_text TEXT NOT NULL,
    created_at TEXT NOT NULL,
    CHECK (alert_id IS NOT NULL OR investigation_id IS NOT NULL)
);

-- 11. Evaluation Runs
CREATE TABLE IF NOT EXISTS evaluation_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dataset_name TEXT NOT NULL,
    run_timestamp TEXT NOT NULL,
    total_rules_evaluated INTEGER NOT NULL,
    overall_precision REAL,
    overall_recall REAL,
    overall_f1 REAL,
    overall_fpr REAL,
    execution_duration_sec REAL
);

-- 12. Evaluation Results
CREATE TABLE IF NOT EXISTS evaluation_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES evaluation_runs(id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL REFERENCES detection_rules(id) ON DELETE CASCADE,
    true_positives INTEGER NOT NULL DEFAULT 0,
    false_positives INTEGER NOT NULL DEFAULT 0,
    true_negatives INTEGER NOT NULL DEFAULT 0,
    false_negatives INTEGER NOT NULL DEFAULT 0,
    precision REAL,
    recall REAL,
    f1_score REAL,
    false_positive_rate REAL
);

-- Performance & Triage Indexes

-- Events table indexes
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_events_proc_guid ON events(process_guid);
CREATE INDEX IF NOT EXISTS idx_events_process_guid ON events(process_guid);
CREATE INDEX IF NOT EXISTS idx_events_parent_proc_guid ON events(parent_process_guid);
CREATE INDEX IF NOT EXISTS idx_events_parent_process_guid ON events(parent_process_guid);
CREATE INDEX IF NOT EXISTS idx_events_comp_ts ON events(computer, timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_events_computer_ts ON events(computer, timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_events_eid_ts ON events(event_id, timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_events_category ON events(event_category, timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_events_category_ts ON events(event_category, timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(user);
CREATE INDEX IF NOT EXISTS idx_events_job_id ON events(import_job_id);
CREATE INDEX IF NOT EXISTS idx_events_hash ON events(event_hash);

-- Processes table indexes
CREATE INDEX IF NOT EXISTS idx_processes_parent_guid ON processes(parent_process_guid);
CREATE INDEX IF NOT EXISTS idx_processes_parent ON processes(parent_process_guid);
CREATE INDEX IF NOT EXISTS idx_processes_start_time ON processes(start_time);
CREATE INDEX IF NOT EXISTS idx_processes_image ON processes(image);

-- Alerts table indexes
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_comp ON alerts(computer);
CREATE INDEX IF NOT EXISTS idx_alerts_computer ON alerts(computer);
CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);

-- Alert Evidence table indexes
CREATE INDEX IF NOT EXISTS idx_evidence_alert ON alert_evidence(alert_id);
CREATE INDEX IF NOT EXISTS idx_evidence_event ON alert_evidence(event_id);

-- Analyst Notes table indexes
CREATE INDEX IF NOT EXISTS idx_notes_alert ON analyst_notes(alert_id);
CREATE INDEX IF NOT EXISTS idx_notes_investigation ON analyst_notes(investigation_id);

-- Evaluation Results indexes
CREATE INDEX IF NOT EXISTS idx_eval_results_run ON evaluation_results(run_id);
CREATE INDEX IF NOT EXISTS idx_eval_results_rule ON evaluation_results(rule_id);
