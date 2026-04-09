"""create_advisory_tables

Revision ID: 992c03d4f851
Revises:
Create Date: 2026-04-09 15:12:17.655181

"""
from typing import Sequence, Union
from alembic import op


revision: str = '992c03d4f851'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS advisories (
            advisory_id         VARCHAR(50)  PRIMARY KEY,
            title               TEXT,
            url                 VARCHAR(500),
            s3_raw_path         VARCHAR(500),
            published_date      DATE,
            advisory_type       VARCHAR(50),
            co_authors          ARRAY,
            threat_actors       ARRAY,
            cve_ids_mentioned   ARRAY,
            mitre_ids_mentioned ARRAY,
            triplets_extracted  BOOLEAN DEFAULT FALSE,
            loaded_to_neo4j     BOOLEAN DEFAULT FALSE,
            ingested_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP()
        )
    """)

    op.execute("""
        CREATE TABLE IF NOT EXISTS advisory_chunks (
            chunk_id            VARCHAR(100) PRIMARY KEY,
            advisory_id         VARCHAR(50)  REFERENCES advisories(advisory_id),
            chunk_index         INTEGER,
            section_name        VARCHAR(100),
            chunk_text          TEXT,
            token_count         INTEGER,
            content_hash        VARCHAR(64),
            cve_ids             ARRAY,
            cwe_ids             ARRAY,
            mitre_tech_ids      ARRAY,
            chunk_embedding     VECTOR(FLOAT, 768),
            triplets_extracted  BOOLEAN DEFAULT FALSE,
            extraction_model    VARCHAR(50),
            extracted_at        TIMESTAMP,
            ingested_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP()
        )
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS advisory_chunks")
    op.execute("DROP TABLE IF EXISTS advisories")
