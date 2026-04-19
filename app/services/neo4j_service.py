"""Neo4j database service."""
import logging
from typing import Any, Optional

from neo4j import GraphDatabase, Driver
from app.config import get_settings

logger = logging.getLogger(__name__)


def _session_kwargs(database: Optional[str]) -> dict[str, Any]:
    if database:
        return {"database": database}
    return {}


class Neo4jService:
    """Service for Neo4j database operations."""

    def __init__(self):
        self.settings = get_settings()
        self._driver: Optional[Driver] = None

    def connect(self) -> Driver:
        """Establish connection to Neo4j."""
        if self._driver is None:
            s = self.settings
            uri = (s.neo4j_uri or "").strip()
            if not uri:
                raise ValueError("NEO4J_URI is not set")
            user = (s.neo4j_username or "neo4j").strip()
            password = s.neo4j_password or ""
            driver = GraphDatabase.driver(uri, auth=(user, password))
            try:
                # Fails fast on bad Aura credentials (clearer than first query).
                driver.verify_authentication()
            except Exception:
                driver.close()
                raise
            self._driver = driver
        return self._driver

    def disconnect(self) -> None:
        """Close the Neo4j driver."""
        if self._driver is not None:
            self._driver.close()
            self._driver = None

    def _default_database(self) -> Optional[str]:
        d = (self.settings.neo4j_database or "").strip()
        return d or None

    async def health_check(self) -> tuple[bool, Optional[str]]:
        """Check if Neo4j connection is healthy."""
        try:
            driver = self.connect()
            driver.verify_authentication()
            driver.verify_connectivity()
            return True, None
        except Exception as e:
            return False, str(e)

    def execute_query(
        self,
        query: str,
        parameters: Optional[dict[str, Any]] = None,
        database: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Execute a Cypher query and return results as list of dicts."""
        driver = self.connect()
        db = database if database is not None else self._default_database()
        with driver.session(**_session_kwargs(db)) as session:
            result = session.run(query, parameters or {})
            return [record.data() for record in result]

    def execute_write(
        self,
        query: str,
        parameters: Optional[dict[str, Any]] = None,
        database: Optional[str] = None,
    ) -> None:
        """Execute a write Cypher query."""
        driver = self.connect()
        db = database if database is not None else self._default_database()
        with driver.session(**_session_kwargs(db)) as session:
            session.run(query, parameters or {})


# Singleton instance
_neo4j_service: Optional[Neo4jService] = None


def get_neo4j_service() -> Neo4jService:
    """Get or create Neo4j service singleton."""
    global _neo4j_service
    if _neo4j_service is None:
        _neo4j_service = Neo4jService()
    return _neo4j_service
