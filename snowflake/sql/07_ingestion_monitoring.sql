-- Ingestion checkpoints + pipeline_runs extensions + KEV / CVE sync flags.
-- Prerequisite: 02_curated_core.sql, 03_monitor.sql applied.

USE DATABASE CTI_PLATFORM_DATABASE;
USE SCHEMA PUBLIC;

-- High-water marks and arbitrary checkpoint metadata per logical source.
CREATE TABLE IF NOT EXISTS ingestion_checkpoints (
    source VARCHAR(100) PRIMARY KEY,
    watermark_ts TIMESTAMP_NTZ,
    watermark_date DATE,
    updated_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    last_run_id VARCHAR(100),
    notes VARIANT
);

-- Airflow + slice metadata (idempotent re-run: new run_id per task try).
ALTER TABLE pipeline_runs ADD COLUMN IF NOT EXISTS airflow_dag_run_id VARCHAR(100);
ALTER TABLE pipeline_runs ADD COLUMN IF NOT EXISTS airflow_task_id VARCHAR(200);
ALTER TABLE pipeline_runs ADD COLUMN IF NOT EXISTS logical_source VARCHAR(100);
ALTER TABLE pipeline_runs ADD COLUMN IF NOT EXISTS stats VARIANT;
ALTER TABLE pipeline_runs ADD COLUMN IF NOT EXISTS watermark_from TIMESTAMP_NTZ;
ALTER TABLE pipeline_runs ADD COLUMN IF NOT EXISTS watermark_to TIMESTAMP_NTZ;

ALTER TABLE cve_records ADD COLUMN IF NOT EXISTS kev_neo4j_dirty BOOLEAN DEFAULT FALSE;

ALTER TABLE kev_pending_fetch ADD COLUMN IF NOT EXISTS kev_ransomware_use VARCHAR(50);
ALTER TABLE kev_pending_fetch ADD COLUMN IF NOT EXISTS kev_required_action TEXT;
ALTER TABLE kev_pending_fetch ADD COLUMN IF NOT EXISTS kev_due_date DATE;
ALTER TABLE kev_pending_fetch ADD COLUMN IF NOT EXISTS kev_vendor_project VARCHAR(100);
ALTER TABLE kev_pending_fetch ADD COLUMN IF NOT EXISTS kev_product VARCHAR(100);
