"""server status (down alerts)

Revision ID: 0009
Revises: 0008
Create Date: 2026-07-07

"""
from alembic import op
import sqlalchemy as sa

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "server_status",
        sa.Column("server_id", sa.Integer(), primary_key=True),
        sa.Column("online", sa.Boolean(), nullable=False),
        sa.Column(
            "changed_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_table("server_status")
