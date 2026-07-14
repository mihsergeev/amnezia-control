"""server position (manual ordering of servers & groups)

Revision ID: 0020
Revises: 0019
Create Date: 2026-07-14
"""
from alembic import op
import sqlalchemy as sa

revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "servers",
        sa.Column("position", sa.Integer(), nullable=False, server_default="0"),
    )
    # бэкфилл: сохраняем текущий порядок (по id), дальше пользователь перетащит
    op.execute("UPDATE servers SET position = id")


def downgrade() -> None:
    op.drop_column("servers", "position")
