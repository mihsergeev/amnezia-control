"""server_status.drop_alerted / drop_alerted_at - состояние алерта «пропали клиенты»

Раньше оно жило в памяти, и после каждого рестарта панели алерт приходил
заново про ту же самую просадку. При миграции всем серверам ставится
drop_alerted_at = сейчас: про текущие просадки старая версия уже написала.

Revision ID: 0026
Revises: 0025
"""

import sqlalchemy as sa
from alembic import op

revision = "0026"
down_revision = "0025"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "server_status",
        sa.Column("drop_alerted", sa.Boolean(), server_default=sa.false(), nullable=False),
    )
    op.add_column(
        "server_status",
        sa.Column("drop_alerted_at", sa.DateTime(timezone=True), nullable=True),
    )
    # просадки, про которые старая версия уже прислала алерт, не должны прийти
    # снова сразу после обновления: сутки тишины от момента миграции
    op.execute(sa.text("UPDATE server_status SET drop_alerted_at = CURRENT_TIMESTAMP"))


def downgrade() -> None:
    with op.batch_alter_table("server_status") as batch:
        batch.drop_column("drop_alerted_at")
        batch.drop_column("drop_alerted")
