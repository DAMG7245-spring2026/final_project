import os
from logging.config import fileConfig
from urllib.parse import quote_plus

from sqlalchemy import engine_from_config, pool
from alembic import context
from alembic.ddl.impl import DefaultImpl
from dotenv import load_dotenv

# Register Snowflake dialect with Alembic
class SnowflakeImpl(DefaultImpl):
    __dialect__ = "snowflake"

load_dotenv()

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Build Snowflake URL from .env
account   = os.environ["SNOWFLAKE_ACCOUNT"]
user      = os.environ["SNOWFLAKE_USER"]
password  = quote_plus(os.environ["SNOWFLAKE_PASSWORD"])  # handles special chars like #
database  = os.environ["SNOWFLAKE_DATABASE"]
schema    = os.environ["SNOWFLAKE_SCHEMA"]
warehouse = os.environ["SNOWFLAKE_WAREHOUSE"]
role      = os.environ.get("SNOWFLAKE_ROLE", "SYSADMIN")

snowflake_url = (
    f"snowflake://{user}:{password}@{account}"
    f"/{database}/{schema}?warehouse={warehouse}&role={role}"
)
# configparser treats % as interpolation; escape it by doubling
config.set_main_option("sqlalchemy.url", snowflake_url.replace("%", "%%"))

target_metadata = None


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
