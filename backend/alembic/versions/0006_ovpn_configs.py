"""stored openvpn client configs (vpn://)

Revision ID: 0006
Revises: 0005
Create Date: 2026-07-06

"""
from alembic import op
import sqlalchemy as sa

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ovpn_configs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("server_id", sa.Integer(), nullable=False, index=True),
        sa.Column("client_id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("config_amnezia", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "server_id", "client_id", name="uq_ovpn_configs_server_client"
        ),
    )


def downgrade() -> None:
    op.drop_table("ovpn_configs")
