"""action audit log

Revision ID: 0007
Revises: 0006
Create Date: 2026-07-07

"""
from alembic import op
import sqlalchemy as sa

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "audit_log",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "ts",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
            index=True,
        ),
        sa.Column("username", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("action", sa.String(length=48), nullable=False),
        sa.Column("target", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("detail", sa.Text(), nullable=False, server_default=""),
    )


def downgrade() -> None:
    op.drop_table("audit_log")
