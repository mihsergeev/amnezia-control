"""Store an optional endpoint for client VPN profiles.

Revision ID: 0034
Revises: 0033
"""

import sqlalchemy as sa
from alembic import op

revision = "0034"
down_revision = "0033"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "servers", sa.Column("client_endpoint", sa.String(255), nullable=False, server_default="")
    )


def downgrade() -> None:
    op.drop_column("servers", "client_endpoint")
