"""server check status columns

Revision ID: 0002
Revises: 0001
Create Date: 2026-07-06

"""
from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("servers", sa.Column("last_check_ok", sa.Boolean(), nullable=True))
    op.add_column(
        "servers",
        sa.Column("last_check_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "servers",
        sa.Column("last_check_info", sa.Text(), nullable=False, server_default=""),
    )


def downgrade() -> None:
    op.drop_column("servers", "last_check_info")
    op.drop_column("servers", "last_check_at")
    op.drop_column("servers", "last_check_ok")
