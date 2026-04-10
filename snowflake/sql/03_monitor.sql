-- Pipeline run audit trail in PUBLIC (alongside other CTI tables).
-- Prerequisite: run 01_schemas.sql first.

USE DATABASE CTI_PLATFORM_DATABASE;
USE SCHEMA PUBLIC;

CREATE TABLE IF NOT EXISTS pipeline_runs (
    run_id VARCHAR(100) PRIMARY KEY,
    dag_id VARCHAR(100),
    source VARCHAR(50),
    records_fetched INTEGER,
    records_new INTEGER,
    records_rejected INTEGER,
    llm_calls_made INTEGER,
    cache_hits INTEGER,
    started_at TIMESTAMP_NTZ,
    completed_at TIMESTAMP_NTZ,
    status VARCHAR(20),
    error_message TEXT
);
