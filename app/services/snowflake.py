"""Snowflake database service."""
import logging
from contextlib import contextmanager
from typing import Any, Generator, Optional
from uuid import UUID
import snowflake.connector
from snowflake.connector import SnowflakeConnection
from snowflake.connector.cursor import SnowflakeCursor
from app.config import get_settings

logger = logging.getLogger(__name__)


class SnowflakeService:
    """Service for Snowflake database operations."""
    
    def __init__(self):
        self.settings = get_settings()
        self._connection: Optional[SnowflakeConnection] = None
    
    def _get_connection_params(self) -> dict[str, Any]:
        """Get connection parameters."""
        return {
            "account": self.settings.snowflake_account,
            "user": self.settings.snowflake_user,
            "password": self.settings.snowflake_password,
            "database": self.settings.snowflake_database,
            "schema": self.settings.snowflake_schema,
            "warehouse": self.settings.snowflake_warehouse,
        }
    
    def connect(self) -> SnowflakeConnection:
        """Establish connection to Snowflake."""
        if self._connection is None or self._connection.is_closed():
            self._connection = snowflake.connector.connect(
                **self._get_connection_params()
            )
        return self._connection
    
    def disconnect(self) -> None:
        """Close the Snowflake connection."""
        if self._connection and not self._connection.is_closed():
            self._connection.close()
            self._connection = None
    
    @contextmanager
    def cursor(self) -> Generator[SnowflakeCursor, None, None]:
        """Context manager for database cursor."""
        conn = self.connect()
        cur = conn.cursor()
        try:
            yield cur
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            cur.close()
    
    async def health_check(self) -> tuple[bool, Optional[str]]:
        """Check if Snowflake connection is healthy."""
        try:
            with self.cursor() as cur:
                cur.execute("SELECT 1")
                result = cur.fetchone()
                return result is not None, None
        except Exception as e:
            return False, str(e)
    
    def execute_query(
        self, 
        query: str, 
        params: Optional[tuple] = None
    ) -> list[dict[str, Any]]:
        """Execute a query and return results as list of dicts."""
        with self.cursor() as cur:
            cur.execute(query, params)
            columns = [desc[0].lower() for desc in cur.description] if cur.description else []
            rows = cur.fetchall()
            return [dict(zip(columns, row)) for row in rows]
    
    def execute_one(
        self, 
        query: str, 
        params: Optional[tuple] = None
    ) -> Optional[dict[str, Any]]:
        """Execute a query and return single result."""
        results = self.execute_query(query, params)
        return results[0] if results else None
    
    def execute_write(
        self, 
        query: str, 
        params: Optional[tuple] = None
    ) -> int:
        """Execute an INSERT/UPDATE/DELETE and return affected rows."""
        with self.cursor() as cur:
            cur.execute(query, params)
            return cur.rowcount


# Singleton instance
_snowflake_service: Optional[SnowflakeService] = None


def get_snowflake_service() -> SnowflakeService:
    """Get or create Snowflake service singleton."""
    global _snowflake_service
    if _snowflake_service is None:
        _snowflake_service = SnowflakeService()
    return _snowflake_service