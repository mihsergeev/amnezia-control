"""client limits (expiry)

Revision ID: 0008
Revises: 0007
Create Date: 2026-07-07

"""
from alembic import op
import sqlalchemy as sa

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "client_limits",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("server_id", sa.Integer(), nullable=False, index=True),
        sa.Column("protocol", sa.String(length=16), nullable=False),
        sa.Column("client_id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False, server_default=""),
        sa.Column(
            "expires_at", sa.DateTime(timezone=True), nullable=True, index=True
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "server_id", "protocol", "client_id", name="uq_client_limits"
        ),
    )


def downgrade() -> None:
    op.drop_table("client_limits")
