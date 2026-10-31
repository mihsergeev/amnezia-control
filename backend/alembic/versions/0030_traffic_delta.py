"""traffic_samples.rx_delta/tx_delta - прирост трафика по клиентам

Revision ID: 0030
Revises: 0029
"""

import sqlalchemy as sa
from alembic import op

revision = "0030"
down_revision = "0029"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("traffic_samples", sa.Column("rx_delta", sa.BigInteger(), nullable=True))
    op.add_column("traffic_samples", sa.Column("tx_delta", sa.BigInteger(), nullable=True))


def downgrade() -> None:
    op.drop_column("traffic_samples", "tx_delta")
    op.drop_column("traffic_samples", "rx_delta")
