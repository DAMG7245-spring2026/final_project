"""Configuration management using Pydantic Settings."""
from functools import lru_cache

from pydantic import field_validator
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

    # LiteLLM router
    # Per-task model mapping. Values must be LiteLLM-compatible model IDs
    # (e.g. "gpt-4o", "gpt-4o-mini", "anthropic/claude-sonnet-4-6").
    llm_model_cypher_generation: str = "gpt-4o"
    llm_model_answer_generation: str = "gpt-4o"
    llm_model_doctype_classification: str = "gpt-4o-mini"
    llm_model_default: str = "gpt-4o-mini"
    # Daily USD budget. When exceeded, LLMRouter raises BudgetExceededError.
    llm_daily_budget_usd: float = 5.0
    # When false, budget is only tracked + logged (soft mode), not enforced.
    llm_budget_enforce: bool = True

    # Structured logging (structlog) — applies to the whole app, not just LLM calls.
    # "json"    = JSONRenderer (prod/containers, machine-parseable)
    # "console" = ConsoleRenderer (dev, colorized key=value)
    # "auto"    = console when debug=True else json
    log_format: str = "auto"
    log_level: str = "INFO"
    # Optional sink for every structured log line. Empty = stderr only.
    log_file: str = ""

    # Neo4j
    neo4j_uri: str = ""
    neo4j_username: str = "neo4j"
    neo4j_password: str = ""
    # When empty, drivers use the server home / default database (required on some Aura tiers).
    neo4j_database: str = ""

    @field_validator(
        "neo4j_uri",
        "neo4j_username",
        "neo4j_password",
        "neo4j_database",
        mode="before",
    )
    @classmethod
    def _strip_neo4j_whitespace(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if isinstance(v, str):
            return v.strip()
        return v

    # Cache TTLs (seconds)
    cache_ttl_company: int = 300  # 5 minutes
    cache_ttl_industry: int = 3600  # 1 hour
    cache_ttl_assessment: int = 120  # 2 minutes
    cache_ttl_dimension_weights: int = 86400  # 24 hours


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
