"""Keep manual server geography separate from automatic discovery."""

import sqlalchemy as sa
from alembic import op

revision = "0038"
down_revision = "0037"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("servers", sa.Column("country_override", sa.String(2), nullable=False, server_default=""))


def downgrade() -> None:
    op.drop_column("servers", "country_override")
