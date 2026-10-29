"""node_metrics.cpu_busy/cpu_total/cpu_pct/psi_cpu - настоящая загрузка CPU вместо load/ядра

Revision ID: 0029
Revises: 0028
"""

import sqlalchemy as sa
from alembic import op

revision = "0029"
down_revision = "0028"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "node_metrics",
        sa.Column("cpu_busy", sa.BigInteger(), nullable=False, server_default="0"),
    )
    op.add_column(
        "node_metrics",
        sa.Column("cpu_total", sa.BigInteger(), nullable=False, server_default="0"),
    )
    op.add_column("node_metrics", sa.Column("cpu_pct", sa.Float(), nullable=True))
    op.add_column("node_metrics", sa.Column("psi_cpu", sa.Float(), nullable=True))


def downgrade() -> None:
    op.drop_column("node_metrics", "psi_cpu")
    op.drop_column("node_metrics", "cpu_pct")
    op.drop_column("node_metrics", "cpu_total")
    op.drop_column("node_metrics", "cpu_busy")
