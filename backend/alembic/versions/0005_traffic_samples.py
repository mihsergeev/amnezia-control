"""traffic samples for stats

Revision ID: 0005
Revises: 0004
Create Date: 2026-07-06

"""
from alembic import op
import sqlalchemy as sa

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "traffic_samples",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("server_id", sa.Integer(), nullable=False, index=True),
        sa.Column(
            "ts",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
            index=True,
        ),
        sa.Column("rx_total", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("tx_total", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("clients_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("clients_online", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_table("traffic_samples")
