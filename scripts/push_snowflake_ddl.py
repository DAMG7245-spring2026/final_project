#!/usr/bin/env python3
"""Apply snowflake/sql/*.sql to Snowflake using credentials from .env (project root)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import snowflake.connector
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
SQL_DIR = ROOT / "snowflake" / "sql"
SQL_FILES = [
    SQL_DIR / "01_schemas.sql",
    SQL_DIR / "02_curated_core.sql",
    SQL_DIR / "03_monitor.sql",
    SQL_DIR / "04_demonstration_pool.sql",
]


def main() -> int:
    load_dotenv(ROOT / ".env")
    account = os.environ.get("SNOWFLAKE_ACCOUNT", "").strip()
    user = os.environ.get("SNOWFLAKE_USER", "").strip()
    password = os.environ.get("SNOWFLAKE_PASSWORD", "")
    warehouse = os.environ.get("SNOWFLAKE_WAREHOUSE", "COMPUTE_WH").strip()

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

    for path in SQL_FILES:
        if not path.is_file():
            print(f"SQL file not found: {path}", file=sys.stderr)
            return 1

    conn = snowflake.connector.connect(
        user=user,
        password=password,
        account=account,
        warehouse=warehouse,
    )
    try:
        for path in SQL_FILES:
            sql_text = path.read_text(encoding="utf-8")
            print(f"Executing {path.name} ...")
            list(
                conn.execute_string(
                    sql_text,
                    remove_comments=True,
                    return_cursors=True,
                )
            )
            print(f"  OK: {path.name}")
    except snowflake.connector.errors.Error as e:
        print(f"Snowflake error: {e}", file=sys.stderr)
        return 1
    finally:
        conn.close()

    print("All DDL scripts applied successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
