"""Track availability alert delivery independently for each channel."""

import sqlalchemy as sa
from alembic import op

revision = "0036"
down_revision = "0035"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("server_status", sa.Column("availability_alerts", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("server_status", "availability_alerts")
