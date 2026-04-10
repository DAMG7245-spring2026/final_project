"""Push transformed CWE rows into Snowflake cwe_records (MERGE insert-only)."""

from __future__ import annotations

from typing import Any

from app.services.snowflake import get_snowflake_service

MERGE_SQL = """
MERGE INTO cwe_records AS t
USING (
    SELECT
        %s::VARCHAR AS cwe_id,
        %s::VARCHAR AS name,
        %s::VARCHAR AS abstraction,
        %s::VARCHAR AS status,
        %s::VARCHAR AS description,
        %s::BOOLEAN AS is_deprecated
) AS s
ON t.cwe_id = s.cwe_id
WHEN NOT MATCHED THEN
    INSERT (cwe_id, name, abstraction, status, description, is_deprecated)
    VALUES (s.cwe_id, s.name, s.abstraction, s.status, s.description, s.is_deprecated)
"""


def load_cwe_records_to_snowflake(records: list[dict[str, Any]]) -> int:
    """
    MERGE each row into cwe_records (insert when cwe_id not present).
    Returns number of rows processed (not necessarily newly inserted).
    """
    if not records:
        return 0
    sf = get_snowflake_service()
    n = 0
    with sf.cursor() as cur:
        for r in records:
            cur.execute(
                MERGE_SQL,
                (
                    r["cwe_id"],
                    r["name"],
                    r["abstraction"],
                    r["status"],
                    r["description"],
                    r["is_deprecated"],
                ),
            )
            n += 1
    return n
