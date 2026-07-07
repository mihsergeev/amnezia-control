"""per-client traffic samples

Revision ID: 0013
Revises: 0012
Create Date: 2026-07-07

"""
from alembic import op
import sqlalchemy as sa

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "client_traffic_samples",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("server_id", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(length=16), nullable=False),
        sa.Column("client_id", sa.String(length=64), nullable=False),
        sa.Column("rx", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("tx", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column(
            "ts", sa.DateTime(timezone=True), server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("ix_cts_server_id", "client_traffic_samples", ["server_id"])
    op.create_index("ix_cts_ts", "client_traffic_samples", ["ts"])
    op.create_index(
        "ix_cts_lookup",
        "client_traffic_samples",
        ["server_id", "protocol", "client_id", "ts"],
    )


def downgrade() -> None:
    op.drop_index("ix_cts_lookup", table_name="client_traffic_samples")
    op.drop_index("ix_cts_ts", table_name="client_traffic_samples")
    op.drop_index("ix_cts_server_id", table_name="client_traffic_samples")
    op.drop_table("client_traffic_samples")
