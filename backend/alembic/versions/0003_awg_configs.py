"""stored awg client configs

Revision ID: 0003
Revises: 0002
Create Date: 2026-07-06

"""
from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "awg_configs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("server_id", sa.Integer(), nullable=False, index=True),
        sa.Column("public_key", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("config", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint("server_id", "public_key", name="uq_awg_configs_server_pub"),
    )


def downgrade() -> None:
    op.drop_table("awg_configs")
