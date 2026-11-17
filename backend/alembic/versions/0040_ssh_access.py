"""Explicit SSH access policy and one-hop transport; no remote mutations."""
import sqlalchemy as sa
from alembic import op

revision = "0040"
down_revision = "0039"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("servers", sa.Column("ssh_jump_server_id", sa.Integer(), nullable=True))
    op.add_column("servers", sa.Column("ssh_source_mode", sa.String(16), nullable=False, server_default="panel"))
    op.add_column("servers", sa.Column("ssh_source_ips", sa.JSON(), nullable=False, server_default="[]"))
    op.add_column("servers", sa.Column("ssh_firewall_mode", sa.String(16), nullable=False, server_default="add"))
    op.create_table("ssh_access_changes",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("server_id", sa.Integer(), nullable=False),
        sa.Column("phase", sa.String(16), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False))
    op.create_index("ix_ssh_access_changes_server_id", "ssh_access_changes", ["server_id"])


def downgrade() -> None:
    if op.get_bind().execute(sa.text("SELECT COUNT(*) FROM ssh_access_changes WHERE phase IN ('applying','finalizing')")).scalar_one():
        raise RuntimeError("Resolve pending SSH access changes before downgrading")
    if op.get_bind().execute(sa.text("SELECT COUNT(*) FROM servers WHERE ssh_jump_server_id IS NOT NULL OR ssh_source_mode != 'panel' OR ssh_firewall_mode != 'add' OR CAST(ssh_source_ips AS TEXT) != '[]'")).scalar_one():
        raise RuntimeError("Switch SSH nodes to direct access before downgrading")
    for column in ("ssh_firewall_mode", "ssh_source_ips", "ssh_source_mode", "ssh_jump_server_id"):
        op.drop_column("servers", column)
    op.drop_index("ix_ssh_access_changes_server_id", table_name="ssh_access_changes")
    op.drop_table("ssh_access_changes")
