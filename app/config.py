"""Configuration management using Pydantic Settings."""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_name: str = "CTI Platform"
    app_version: str = "1.0.0"
    debug: bool = False

    # Snowflake
    snowflake_account: str = ""
    snowflake_user: str = ""
    snowflake_password: str = ""
    snowflake_database: str = "CTI_PLATFORM_DATABASE"
    snowflake_schema: str = "PUBLIC"
    snowflake_warehouse: str = "COMPUTE_WH"

    # Redis
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0

    # NVD API 2.0 (optional key; higher rate limits)
    nvd_api_key: str = ""
    # If set, seconds between paginated NVD requests (overrides key-based default).
    nvd_min_request_interval_sec: float | None = None

    # AWS S3
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    aws_region: str = "us-east-1"
    s3_bucket: str = ""

    # OpenAI
    openai_api_key: str = ""

    # Neo4j
    neo4j_uri: str = ""
    neo4j_username: str = "neo4j"
    neo4j_password: str = ""

    # Cache TTLs (seconds)
    cache_ttl_company: int = 300  # 5 minutes
    cache_ttl_industry: int = 3600  # 1 hour
    cache_ttl_assessment: int = 120  # 2 minutes
    cache_ttl_dimension_weights: int = 86400  # 24 hours


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
