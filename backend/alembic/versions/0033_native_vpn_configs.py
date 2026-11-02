"""Store native WireGuard and OpenVPN profiles without mixing legacy clients.

Revision ID: 0033
Revises: 0032
"""

import sqlalchemy as sa
from alembic import op

revision = "0033"
down_revision = "0032"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "native_vpn_configs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("server_id", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(16), nullable=False),
        sa.Column("client_id", sa.String(64), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("config", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("server_id", "protocol", "client_id"),
    )
    op.create_index("ix_native_vpn_configs_server_id", "native_vpn_configs", ["server_id"])


def downgrade() -> None:
    # Refuse a rollback that would silently erase clients' only private keys.
    if op.get_bind().execute(sa.text("SELECT 1 FROM native_vpn_configs LIMIT 1")).first():
        raise RuntimeError("Export and remove native VPN profiles before downgrading the schema")
    op.drop_index("ix_native_vpn_configs_server_id", table_name="native_vpn_configs")
    op.drop_table("native_vpn_configs")
