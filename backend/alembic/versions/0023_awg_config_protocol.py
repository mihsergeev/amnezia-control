"""awg_configs.protocol - протокол выданного конфига AWG (awg, awg3, awglegacy)

Таблица общая для всех AWG, и без протокола поиск и массовый отзыв считали
клиента 3.1 или Legacy клиентом 2.0: отзыв уходил на контейнер 2.0, панель
отчитывалась "отозвано", а клиент продолжал работать. Существующие строки
размечаем по таблицам, где протокол уже есть: кэш имен с нод, сроки, заметки.

Revision ID: 0023
Revises: 0022
"""

import sqlalchemy as sa
from alembic import op

revision = "0023"
down_revision = "0022"
branch_labels = None
depends_on = None

_SOURCES = ("client_names", "client_limits", "awg_notes")
_ID_COL = {"client_names": "client_id", "client_limits": "client_id", "awg_notes": "public_key"}


def upgrade() -> None:
    op.add_column(
        "awg_configs",
        sa.Column("protocol", sa.String(length=16), server_default="awg", nullable=False),
    )
    for table in _SOURCES:
        col = _ID_COL[table]
        op.execute(
            f"""
            UPDATE awg_configs SET protocol = (
                SELECT s.protocol FROM {table} s
                WHERE s.server_id = awg_configs.server_id
                  AND s.{col} = awg_configs.public_key
                  AND s.protocol IN ('awg3', 'awglegacy')
                LIMIT 1
            )
            WHERE protocol = 'awg' AND EXISTS (
                SELECT 1 FROM {table} s
                WHERE s.server_id = awg_configs.server_id
                  AND s.{col} = awg_configs.public_key
                  AND s.protocol IN ('awg3', 'awglegacy')
            )
            """
        )


def downgrade() -> None:
    with op.batch_alter_table("awg_configs") as batch:
        batch.drop_column("protocol")
