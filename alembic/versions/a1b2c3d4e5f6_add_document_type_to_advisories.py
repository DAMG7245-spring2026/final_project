"""add_document_type_to_advisories

Revision ID: a1b2c3d4e5f6
Revises: 992c03d4f851
Create Date: 2026-04-10 00:00:00.000000

"""
from typing import Sequence, Union
from alembic import op


revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, Sequence[str], None] = '992c03d4f851'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE advisories
        ADD COLUMN IF NOT EXISTS document_type VARCHAR(32)
    """)


def downgrade() -> None:
    op.execute("""
        ALTER TABLE advisories
        DROP COLUMN IF EXISTS document_type
    """)
