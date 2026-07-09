"""server group

Revision ID: 0014
Revises: 0013
Create Date: 2026-07-08

"""
from alembic import op
import sqlalchemy as sa

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "servers",
        sa.Column("group_name", sa.String(length=64), nullable=False,
                  server_default=""),
    )


def downgrade() -> None:
    op.drop_column("servers", "group_name")
