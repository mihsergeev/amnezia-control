"""per-client panel notes

Revision ID: 0004
Revises: 0003
Create Date: 2026-07-06

"""
from alembic import op
import sqlalchemy as sa

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "awg_notes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("server_id", sa.Integer(), nullable=False, index=True),
        sa.Column("public_key", sa.String(length=64), nullable=False),
        sa.Column("note", sa.Text(), nullable=False, server_default=""),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint("server_id", "public_key", name="uq_awg_notes_server_pub"),
    )


def downgrade() -> None:
    op.drop_table("awg_notes")
