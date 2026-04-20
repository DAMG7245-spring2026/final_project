-- Extracted triplets from all advisory reports via Phase 1 LLM pipeline.
-- Prerequisite: advisories table must exist.

USE DATABASE CTI_PLATFORM_DATABASE;
USE SCHEMA PUBLIC;

CREATE TABLE IF NOT EXISTS extracted_triplets (
    triplet_id   VARCHAR(100) PRIMARY KEY,
    advisory_id  VARCHAR(50)  REFERENCES advisories(advisory_id),
    subject      VARCHAR(500),
    relation     VARCHAR(50),
    object       VARCHAR(500),
    extracted_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
);

COMMENT ON TABLE extracted_triplets IS
    'Phase 1: Triplets extracted from all advisories via kNN ICL pipeline (GPT-4o + top-4 demo retrieval).';
