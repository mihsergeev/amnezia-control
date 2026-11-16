"""Durable recovery of AWG node and profile settings changes."""

import sqlalchemy as sa
from alembic import op

revision = "0039"
down_revision = "0038"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table("awg_settings_changes",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("server_id", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(16), nullable=False),
        sa.Column("phase", sa.String(16), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False))
    op.create_index("ix_awg_settings_changes_server_id", "awg_settings_changes", ["server_id"])


def downgrade() -> None:
    pending = op.get_bind().execute(sa.text(
        "SELECT COUNT(*) FROM awg_settings_changes WHERE phase NOT IN ('done', 'rolledback')"
    )).scalar_one()
    if pending:
        raise RuntimeError("Resolve pending AWG settings changes before downgrading")
    op.drop_index("ix_awg_settings_changes_server_id", table_name="awg_settings_changes")
    op.drop_table("awg_settings_changes")
