-- Core tables in PUBLIC: NVD (CVE), CWE, KEV pending queue, MITRE ATT&CK.
-- Prerequisite: run 01_schemas.sql first (drops legacy schemas, sets PUBLIC).
-- CISA advisory tables (advisories, advisory_chunks, extracted_triplets) are intentionally omitted.

USE DATABASE CTI_PLATFORM_DATABASE;
USE SCHEMA PUBLIC;

CREATE TABLE IF NOT EXISTS cve_records (
    cve_id VARCHAR(20) PRIMARY KEY,
    source_identifier VARCHAR(100),
    published_date DATE,
    last_modified TIMESTAMP_NTZ,
    vuln_status VARCHAR(50),
    description_en TEXT,
    cvss_version VARCHAR(5),
    cvss_score FLOAT,
    cvss_severity VARCHAR(10),
    attack_vector VARCHAR(20),
    attack_complexity VARCHAR(10),
    privileges_required VARCHAR(10),
    user_interaction VARCHAR(10),
    scope VARCHAR(10),
    confidentiality_impact VARCHAR(10),
    integrity_impact VARCHAR(10),
    exploitability_score FLOAT,
    impact_score FLOAT,
    cwe_ids ARRAY,
    cpe_matches VARIANT,
    has_exploit_ref BOOLEAN DEFAULT FALSE,
    -- KEV enrichment columns — updated by KEV enricher, not NVD
    is_kev BOOLEAN DEFAULT FALSE,
    kev_date_added DATE,
    kev_ransomware_use VARCHAR(50),
    kev_required_action TEXT,
    kev_due_date DATE,
    kev_vendor_project VARCHAR(100),
    kev_product VARCHAR(100),
    raw_json VARIANT,
    loaded_to_neo4j BOOLEAN DEFAULT FALSE,
    neo4j_loaded_at TIMESTAMP_NTZ,
    ingested_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
);

CREATE TABLE IF NOT EXISTS cwe_records (
    cwe_id VARCHAR(20) PRIMARY KEY,
    name VARCHAR(300),
    abstraction VARCHAR(20),
    status VARCHAR(30),
    description TEXT,
    is_deprecated BOOLEAN DEFAULT FALSE,
    loaded_to_neo4j BOOLEAN DEFAULT FALSE,
    ingested_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
);

CREATE TABLE IF NOT EXISTS cve_cwe_mappings (
    mapping_id VARCHAR(100) PRIMARY KEY,
    cve_id VARCHAR(20) NOT NULL REFERENCES cve_records (cve_id),
    cwe_id VARCHAR(20),
    mapping_source VARCHAR(50),
    mapping_type VARCHAR(20),
    loaded_to_neo4j BOOLEAN DEFAULT FALSE,
    ingested_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
);

-- CVEs seen in KEV before a row exists in cve_records; NVD DAG drains this queue.
CREATE TABLE IF NOT EXISTS kev_pending_fetch (
    cve_id VARCHAR(20) PRIMARY KEY,
    kev_date_added DATE,
    queued_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    fetched BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS attack_techniques (
    mitre_id VARCHAR(20) PRIMARY KEY,
    stix_id VARCHAR(100),
    name VARCHAR(200),
    tactic VARCHAR(50),
    description TEXT,
    platforms ARRAY,
    is_subtechnique BOOLEAN DEFAULT FALSE,
    parent_id VARCHAR(20),
    is_deprecated BOOLEAN DEFAULT FALSE,
    is_revoked BOOLEAN DEFAULT FALSE,
    mitre_version VARCHAR(10),
    loaded_to_neo4j BOOLEAN DEFAULT FALSE,
    ingested_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
);

CREATE TABLE IF NOT EXISTS attack_actors (
    actor_name VARCHAR(100) PRIMARY KEY,
    stix_id VARCHAR(100),
    external_id VARCHAR(20),
    aliases ARRAY,
    country VARCHAR(100),
    motivation VARCHAR(100),
    description TEXT,
    target_sectors ARRAY,
    loaded_to_neo4j BOOLEAN DEFAULT FALSE,
    ingested_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
);

CREATE TABLE IF NOT EXISTS attack_mitigations (
    mitigation_id VARCHAR(20) PRIMARY KEY,
    stix_id VARCHAR(100),
    name VARCHAR(200),
    description TEXT,
    loaded_to_neo4j BOOLEAN DEFAULT FALSE,
    ingested_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
);

CREATE TABLE IF NOT EXISTS attack_tactics (
    tactic_id VARCHAR(20) PRIMARY KEY,
    stix_id VARCHAR(100),
    name VARCHAR(100),
    shortname VARCHAR(50),
    description TEXT,
    tactic_order INTEGER,
    loaded_to_neo4j BOOLEAN DEFAULT FALSE,
    ingested_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
);

CREATE TABLE IF NOT EXISTS attack_campaigns (
    campaign_id VARCHAR(100) PRIMARY KEY,
    stix_id VARCHAR(100),
    external_id VARCHAR(20),
    name VARCHAR(200),
    description TEXT,
    loaded_to_neo4j BOOLEAN DEFAULT FALSE,
    ingested_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
);

CREATE TABLE IF NOT EXISTS attack_relationships (
    relationship_id VARCHAR(200) PRIMARY KEY,
    source_stix_id VARCHAR(100),
    source_name VARCHAR(200),
    source_type VARCHAR(50),
    target_stix_id VARCHAR(100),
    target_name VARCHAR(200),
    target_type VARCHAR(50),
    relation_type VARCHAR(50),
    loaded_to_neo4j BOOLEAN DEFAULT FALSE,
    ingested_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
);
