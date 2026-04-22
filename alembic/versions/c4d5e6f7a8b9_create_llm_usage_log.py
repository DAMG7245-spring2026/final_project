"""create_llm_usage_log

Revision ID: c4d5e6f7a8b9
Revises: b2c3d4e5f6a7
Create Date: 2026-04-18 00:00:00.000000

"""

from typing import Sequence, Union

from alembic import op

revision: str = "c4d5e6f7a8b9"
down_revision: Union[str, Sequence[str], None] = "b2c3d4e5f6a7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS llm_usage_log (
            log_id               VARCHAR(36)   DEFAULT UUID_STRING() PRIMARY KEY,
            logged_at            TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
            source               VARCHAR(32),
            operation            VARCHAR(256),
            provider             VARCHAR(64),
            model                VARCHAR(128),
            prompt_tokens        INTEGER,
            completion_tokens    INTEGER,
            total_tokens         INTEGER,
            estimated_cost_usd   NUMBER(14,6),
            success              BOOLEAN       DEFAULT TRUE,
            error_message        VARCHAR(8000),
            metadata             VARIANT
        )
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS llm_usage_log")
