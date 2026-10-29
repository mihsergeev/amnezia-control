"""torrent_block - блокировка торрентов на сервере и счетчик по клиентам, см. app/torrent.py

Revision ID: 0028
Revises: 0027
"""

import sqlalchemy as sa
from alembic import op

revision = "0028"
down_revision = "0027"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "servers",
        sa.Column("torrent_block", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "servers",
        sa.Column("torrent_autopause", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_table(
        "torrent_hits",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("server_id", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(length=16), nullable=False),
        sa.Column("client_id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False, server_default=""),
        sa.Column("hits", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("alerted_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("server_id", "protocol", "client_id"),
    )
    op.create_index("ix_torrent_hits_server_id", "torrent_hits", ["server_id"])


def downgrade() -> None:
    op.drop_index("ix_torrent_hits_server_id", table_name="torrent_hits")
    op.drop_table("torrent_hits")
    op.drop_column("servers", "torrent_autopause")
    op.drop_column("servers", "torrent_block")
