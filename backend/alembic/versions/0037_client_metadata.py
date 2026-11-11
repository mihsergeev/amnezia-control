"""Optional client and device display labels."""

import sqlalchemy as sa
from alembic import op

revision = "0037"
down_revision = "0036"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table("client_metadata",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("server_id", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(16), nullable=False),
        sa.Column("client_id", sa.String(128), nullable=False),
        sa.Column("group_name", sa.String(128), nullable=False, server_default=""),
        sa.Column("device_name", sa.String(128), nullable=False, server_default=""),
        sa.UniqueConstraint("server_id", "protocol", "client_id"))
    op.create_index("ix_client_metadata_server_id", "client_metadata", ["server_id"])


def downgrade() -> None:
    op.drop_index("ix_client_metadata_server_id", table_name="client_metadata")
    op.drop_table("client_metadata")
