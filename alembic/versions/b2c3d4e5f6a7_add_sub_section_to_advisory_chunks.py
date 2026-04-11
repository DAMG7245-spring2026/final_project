"""add_sub_section_to_advisory_chunks

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-04-10 00:00:00.000000

"""
from typing import Sequence, Union
from alembic import op


revision: str = 'b2c3d4e5f6a7'
down_revision: Union[str, Sequence[str], None] = 'a1b2c3d4e5f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE advisory_chunks
        ADD COLUMN IF NOT EXISTS sub_section VARCHAR(200)
    """)


def downgrade() -> None:
    op.execute("""
        ALTER TABLE advisory_chunks
        DROP COLUMN IF EXISTS sub_section
    """)
