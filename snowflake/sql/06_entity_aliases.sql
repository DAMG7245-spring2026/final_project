-- Entity alias mapping table for Phase 2 Entity Alignment.
-- Maps alias names found in extracted_triplets to canonical entity names.
-- Prerequisite: extracted_triplets table must exist.

USE DATABASE CTI_PLATFORM_DATABASE;
USE SCHEMA PUBLIC;

CREATE TABLE IF NOT EXISTS entity_aliases (
    alias_name     VARCHAR(500) PRIMARY KEY,
    canonical_name VARCHAR(500),
    entity_type    VARCHAR(50)
);

COMMENT ON TABLE entity_aliases IS
    'Phase 2: Alias-to-canonical entity mappings produced by cosine similarity + GPT-4o binary classification.';
