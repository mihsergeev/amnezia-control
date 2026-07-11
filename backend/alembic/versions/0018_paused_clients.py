"""paused clients (freeze without revoke)

Revision ID: 0018
Revises: 0017
Create Date: 2026-07-12
"""
from alembic import op
import sqlalchemy as sa

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "paused_clients",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("server_id", sa.Integer(), nullable=False, index=True),
        sa.Column("protocol", sa.String(length=16), nullable=False),
        sa.Column("client_id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False, server_default=""),
        sa.Column("data", sa.Text(), nullable=False, server_default=""),
        sa.Column(
            "paused_at", sa.DateTime(timezone=True),
            server_default=sa.func.now(), nullable=False,
        ),
        sa.UniqueConstraint(
            "server_id", "protocol", "client_id", name="uq_paused_srv_proto_client"
        ),
    )


def downgrade() -> None:
    op.drop_table("paused_clients")
