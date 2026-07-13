"""server country (ISO code for flag)

Revision ID: 0019
Revises: 0018
Create Date: 2026-07-12
"""
from alembic import op
import sqlalchemy as sa

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "servers",
        sa.Column("country", sa.String(length=2), nullable=False, server_default=""),
    )


def downgrade() -> None:
    op.drop_column("servers", "country")
