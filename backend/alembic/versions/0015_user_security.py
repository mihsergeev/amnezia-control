"""user security: token_version + totp_last_counter

Revision ID: 0015
Revises: 0014
Create Date: 2026-07-09

"""
from alembic import op
import sqlalchemy as sa

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("totp_last_counter", sa.BigInteger(), nullable=False,
                  server_default="0"),
    )
    op.add_column(
        "users",
        sa.Column("token_version", sa.Integer(), nullable=False,
                  server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("users", "token_version")
    op.drop_column("users", "totp_last_counter")
