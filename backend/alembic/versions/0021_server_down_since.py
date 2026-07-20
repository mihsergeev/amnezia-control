"""server_status.down_since — таймер антидребезга падений

Хранит момент первого офлайн-наблюдения в текущей серии: алерт о падении
поднимаем только если нода недоступна непрерывно дольше server_down_minutes.
В БД (а не в памяти), чтобы рестарт панели не сбрасывал отсчёт во время аварии.

Revision ID: 0021
Revises: 0020
"""

import sqlalchemy as sa
from alembic import op

revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "server_status",
        sa.Column("down_since", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("server_status", "down_since")
