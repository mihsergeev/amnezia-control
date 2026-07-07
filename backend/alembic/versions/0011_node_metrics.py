"""node resource metrics

Revision ID: 0011
Revises: 0010
Create Date: 2026-07-07

"""
from alembic import op
import sqlalchemy as sa

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "node_metrics",
        sa.Column("server_id", sa.Integer(), primary_key=True),
        sa.Column("cpu_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("load1", sa.Float(), nullable=False, server_default="0"),
        sa.Column("mem_total", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("mem_used", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("disk_total", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("disk_used", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column(
            "uptime_seconds", sa.BigInteger(), nullable=False, server_default="0"
        ),
        sa.Column(
            "disk_alerted", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column(
            "ts", sa.DateTime(timezone=True), server_default=sa.func.now(),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_table("node_metrics")
