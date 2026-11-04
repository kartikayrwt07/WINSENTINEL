-- 002_process_lineage_metadata.sql
-- Add computer hostname scoping and is_synthesized tracking to processes table.

ALTER TABLE processes ADD COLUMN computer TEXT NOT NULL DEFAULT 'UNKNOWN';
ALTER TABLE processes ADD COLUMN is_synthesized INTEGER NOT NULL DEFAULT 0;

-- Additional forensic query and triage indexes
CREATE INDEX IF NOT EXISTS idx_processes_comp_guid ON processes(computer, process_guid);
CREATE INDEX IF NOT EXISTS idx_processes_comp_pid ON processes(computer, process_id, start_time);
CREATE INDEX IF NOT EXISTS idx_processes_computer_pid ON processes(computer, process_id, start_time);
CREATE INDEX IF NOT EXISTS idx_processes_anomalous ON processes(is_anomalous);
