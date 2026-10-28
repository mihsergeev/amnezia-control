"""servers.egress_* - адрес выхода клиентов в интернет, если нода - вход каскада

Панель раз в час спрашивает изнутри amnezia-контейнера, с какого адреса
трафик клиентов уходит в интернет, и показывает путь "сервер -> выход",
когда этот адрес не совпадает с адресом сервера.

Revision ID: 0025
Revises: 0024
"""

import sqlalchemy as sa
from alembic import op

revision = "0025"
down_revision = "0024"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "servers", sa.Column("egress_ip", sa.String(45), server_default="", nullable=False)
    )
    op.add_column(
        "servers",
        sa.Column("egress_country", sa.String(2), server_default="", nullable=False),
    )
    op.add_column(
        "servers",
        sa.Column("egress_org", sa.String(128), server_default="", nullable=False),
    )
    op.add_column(
        "servers", sa.Column("egress_at", sa.DateTime(timezone=True), nullable=True)
    )


def downgrade() -> None:
    with op.batch_alter_table("servers") as batch:
        batch.drop_column("egress_at")
        batch.drop_column("egress_org")
        batch.drop_column("egress_country")
        batch.drop_column("egress_ip")
