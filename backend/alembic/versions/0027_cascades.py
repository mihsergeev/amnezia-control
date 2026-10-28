"""cascades - каскады из двух серверов (вход и выход), см. app/cascade.py

Revision ID: 0027
Revises: 0026
"""

import sqlalchemy as sa
from alembic import op

revision = "0027"
down_revision = "0026"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cascades",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("entry_server_id", sa.Integer(), nullable=False, unique=True),
        sa.Column("exit_server_id", sa.Integer(), nullable=False, unique=True),
        sa.Column("transport", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="installing"),
        sa.Column("error", sa.Text(), nullable=False, server_default=""),
        sa.Column("params", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("probe", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("result", sa.Text(), nullable=False, server_default="{}"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_table("cascades")
