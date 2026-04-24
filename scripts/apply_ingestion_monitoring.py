#!/usr/bin/env python3
"""Apply only snowflake/sql/07_ingestion_monitoring.sql using SNOWFLAKE_* from .env.

Use this when Airflow NVD DAGs fail with ``ingestion_checkpoints`` / ``pipeline_runs`` missing.
Prerequisites: ``02_curated_core.sql`` and ``03_monitor.sql`` already applied (``pipeline_runs``,
``cve_records``, ``kev_pending_fetch`` exist).

For a full greenfield DDL push, use ``scripts/push_snowflake_ddl.py`` instead.

After this script succeeds, if Airflow still gets "not authorized", run the printed GRANT
statements in Snowflake as ACCOUNTADMIN (or schema owner), replacing ROLE_NAME with the
default role used by ``SNOWFLAKE_USER`` in Airflow.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import snowflake.connector
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
SQL_07 = ROOT / "snowflake" / "sql" / "07_ingestion_monitoring.sql"


def _sql_body_without_use_statements(sql: str) -> str:
    lines_out: list[str] = []
    for line in sql.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("--"):
            lines_out.append(line)
            continue
        u = stripped.upper()
        if u.startswith("USE DATABASE") or u.startswith("USE SCHEMA"):
            continue
        lines_out.append(line)
    return "\n".join(lines_out).strip() + "\n"


def main() -> int:
    load_dotenv(ROOT / ".env")
    account = os.environ.get("SNOWFLAKE_ACCOUNT", "").strip()
    user = os.environ.get("SNOWFLAKE_USER", "").strip()
    password = os.environ.get("SNOWFLAKE_PASSWORD", "")
    warehouse = os.environ.get("SNOWFLAKE_WAREHOUSE", "COMPUTE_WH").strip()
    database = os.environ.get("SNOWFLAKE_DATABASE", "CTI_PLATFORM_DATABASE").strip()
    schema = os.environ.get("SNOWFLAKE_SCHEMA", "PUBLIC").strip()

    missing = [
        name
        for name, val in (
            ("SNOWFLAKE_ACCOUNT", account),
            ("SNOWFLAKE_USER", user),
            ("SNOWFLAKE_PASSWORD", password),
        )
        if not val
    ]
    if missing:
        print(f"Missing required environment variables: {missing}", file=sys.stderr)
        return 1

    if not SQL_07.is_file():
        print(f"SQL file not found: {SQL_07}", file=sys.stderr)
        return 1

    raw = SQL_07.read_text(encoding="utf-8")
    body = _sql_body_without_use_statements(raw)
    prelude = f"USE DATABASE {database};\nUSE SCHEMA {schema};\n"
    full_sql = prelude + body

    print(f"Applying 07_ingestion_monitoring.sql to {database}.{schema} ...")
    conn = snowflake.connector.connect(
        user=user,
        password=password,
        account=account,
        warehouse=warehouse,
        database=database,
        schema=schema,
    )
    try:
        list(
            conn.execute_string(
                full_sql,
                remove_comments=True,
                return_cursors=True,
            )
        )
    except snowflake.connector.errors.Error as e:
        print(f"Snowflake error: {e}", file=sys.stderr)
        print(
            "\nIf objects are missing, apply prerequisites first:\n"
            "  poetry run python scripts/push_snowflake_ddl.py\n"
            "or run 02_curated_core.sql and 03_monitor.sql in order.",
            file=sys.stderr,
        )
        return 1
    finally:
        conn.close()

    print("OK: ingestion_checkpoints + pipeline_runs columns + KEV/CVE flags applied.")
    role_hint = os.environ.get("SNOWFLAKE_AIRFLOW_ROLE", "").strip() or "YOUR_AIRFLOW_ROLE"
    print("\nIf the Airflow Snowflake user still cannot read/write, run as admin (replace role):")
    print(f"  GRANT USAGE ON DATABASE {database} TO ROLE {role_hint};")
    print(f"  GRANT USAGE ON SCHEMA {database}.{schema} TO ROLE {role_hint};")
    print(
        f"  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE {database}.{schema}.ingestion_checkpoints TO ROLE {role_hint};"
    )
    print(
        f"  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE {database}.{schema}.pipeline_runs TO ROLE {role_hint};"
    )
    print("\nSet SNOWFLAKE_AIRFLOW_ROLE in .env to print your real role name in the lines above.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
