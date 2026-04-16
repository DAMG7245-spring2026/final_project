-- Demonstration pool for CTINexus-style few-shot triplet extraction.
-- Each row is one advisory's full report text + human-reviewed gold triplets.
-- Prerequisite: advisories table must exist.

USE DATABASE CTI_PLATFORM_DATABASE;
USE SCHEMA PUBLIC;

CREATE TABLE IF NOT EXISTS demonstration_pool (
    demo_id         VARCHAR(20)  PRIMARY KEY,
    advisory_id     VARCHAR(50)  REFERENCES advisories(advisory_id),
    document_type   VARCHAR(50),
    report_text     TEXT,
    gold_triplets   VARIANT,
    demo_embedding  VECTOR(FLOAT, 3072),
    created_at      TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
);

COMMENT ON TABLE demonstration_pool IS
    'Phase 0: ~100 advisories with human-reviewed gold triplets + OpenAI text-embedding-3-large vectors for kNN demo retrieval.';
