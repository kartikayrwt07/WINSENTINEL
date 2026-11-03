# Phase 2: Database Layer & Persistent Storage - Context

**Gathered:** 2026-11-04  
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 2 establishes the persistent storage and relational query foundation for WinSentinel:
- Thread-safe SQLite database manager with WAL mode, foreign key enforcement, and configurable busy timeout.
- Internal versioned SQL migration runner tracking migrations via `schema_migrations` table without external ORM dependencies.
- Normalized relational schema supporting:
  - `imported_files` and `import_jobs`
  - `events` (indexed for timestamps, process_guid, parent_process_guid, event_id, computer, and event_hash)
  - `processes` (process lifespan records)
  - `detection_rules`
  - `alerts` and `alert_evidence`
  - `investigations` and `analyst_notes`
  - `evaluation_runs` and `evaluation_results`
- High-throughput bulk ingestion via `executemany()` in 1,000-record transactions with `INSERT OR IGNORE` deduplication.
- Thread-safe repository layer exposing dynamic parameterized forensic queries with LIMIT/OFFSET pagination and total record counting.

</domain>

<decisions>
## Implementation Decisions

### Database Location & Concurrency Pragmas
- **D-01:** Default storage to `data/winsentinel.db` (configurable via `app/config.py`). Enforce SQLite pragmas: `PRAGMA journal_mode=WAL;`, `PRAGMA foreign_keys=ON;`, `PRAGMA busy_timeout=5000;`, and `PRAGMA synchronous=NORMAL;`. This enables simultaneous non-blocking reads during large ingestion jobs and prevents database lock timeouts.

### Bulk Ingestion & Deduplication
- **D-02:** Implement batch insertion using `cursor.executemany()` chunked in 1,000-event transactions. Utilize `INSERT OR IGNORE INTO events (...) VALUES (...)` bound to the `UNIQUE(event_hash)` constraint. Deduplication counts are calculated atomically by comparing `cursor.rowcount` against chunk length.

### Migration Framework
- **D-03:** Implement a lightweight, self-contained SQL migration runner in `app/database/migrations.py`. Migrations are stored as sequential `.sql` scripts in `app/database/migrations/` (e.g., `001_initial_schema.sql`). Applied migrations are tracked in a `schema_migrations (version INTEGER PRIMARY KEY, name TEXT, applied_at TIMESTAMP)` table. No external migration packages (Alembic/Yoyo) are introduced.

### Forensic Query & Repository Interface
- **D-04:** Implement `EventRepository` and `AlertRepository` in `app/database/repository.py` utilizing dynamic parameterized SQL queries (e.g. `WHERE 1=1 AND computer = ? AND timestamp >= ?`). Avoid string interpolation completely to guarantee SQL injection immunity. Return typed dataclasses/Pydantic models with `total_count` and paginated record slices.

### Developer & Agent Discretion
- Connection management pattern: Thread-local connection pool or context-managed connections (`with get_db_connection() as conn:`) ensuring connections are properly closed.
- Database index tuning: Ensure composite index on `(computer, timestamp_utc)` and `(event_id, timestamp_utc)` for fast dashboard and timeline queries.

</decisions>

<specifics>
## Specific Ideas & Test Coverage

- Unit tests for migration runner (applying initial schema, detecting already applied migrations, rolling back failed migration transactions).
- Concurrency test verifying read operations during active multi-thousand row write batches.
- Performance benchmark verifying 10,000+ events inserted in < 3 seconds using `executemany` chunking in WAL mode.
- SQL injection immunity tests validating that malicious event values (e.g. `'; DROP TABLE events;--`) are treated as inert strings.

</specifics>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing:**
- `.planning/PROJECT.md` — Section 7 (Database Design) and Section 8 (Security Requirements).
- `.planning/REQUIREMENTS.md` — Requirement ALERT-01 and general storage requirements.
- `.planning/ROADMAP.md` — Phase 2 goals, success criteria, and plans breakdown.
- `.planning/phases/WINSENTINEL-01-ingestion-normalization-engine/01-VERIFICATION.md` — Normalization outputs to persist.

</canonical_refs>
