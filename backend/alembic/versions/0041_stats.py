"""Store node resource history and separate monitoring keys from client keys."""
import sqlalchemy as sa
from alembic import op

revision = "0041"
down_revision = "0040"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("api_keys", sa.Column("scope", sa.String(16), nullable=False, server_default="clients"))
    op.create_table(
        "node_resource_samples",
        sa.Column("server_id", sa.Integer(), primary_key=True),
        sa.Column("ts", sa.DateTime(timezone=True), primary_key=True),
        sa.Column("cpu_pct", sa.Float(), nullable=True),
        sa.Column("mem_pct", sa.Float(), nullable=True),
        sa.Column("load1", sa.Float(), nullable=False),
    )
    op.create_index("ix_node_resource_samples_ts", "node_resource_samples", ["ts"])


def downgrade() -> None:
    # Older versions have no way to express read-only monitoring access.
    op.execute(sa.text("UPDATE api_keys SET revoked = true WHERE scope <> 'clients'"))
    op.drop_column("api_keys", "scope")
    op.drop_index("ix_node_resource_samples_ts", table_name="node_resource_samples")
    op.drop_table("node_resource_samples")
