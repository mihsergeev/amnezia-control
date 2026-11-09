"""Keep the identity of each issued batch across request retries."""

import sqlalchemy as sa
from alembic import op

revision = "0035"
down_revision = "0034"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "bulk_client_issues",
        sa.Column("request_id", sa.String(36), primary_key=True),
        sa.Column("server_id", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(16), nullable=False),
        sa.Column("owner_id", sa.Integer(), nullable=False),
        sa.Column("prefix", sa.String(124), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False),
        sa.Column("items", sa.JSON(), nullable=False),
        sa.Column("complete", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_bulk_client_issues_server_id", "bulk_client_issues", ["server_id"])
    pending = sa.text("complete IS false")
    op.create_index("uq_bulk_client_issues_pending", "bulk_client_issues", ["server_id", "protocol"],
                    unique=True, postgresql_where=pending, sqlite_where=pending)


def downgrade() -> None:
    op.drop_table("bulk_client_issues")
