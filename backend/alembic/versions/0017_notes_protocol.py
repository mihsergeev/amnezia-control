"""generic per-client notes: add protocol column to awg_notes

Revision ID: 0017
Revises: 0016
Create Date: 2026-07-12

Заметки теперь общие для всех протоколов (awg/openvpn/xray). Добавляем колонку
protocol (существующие строки — 'awg') и расширяем уникальность до
(server_id, protocol, public_key).
"""
from alembic import op
import sqlalchemy as sa

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("awg_notes", schema=None) as batch:
        batch.add_column(
            sa.Column(
                "protocol", sa.String(length=16),
                nullable=False, server_default="awg",
            )
        )
        batch.drop_constraint("uq_awg_notes_server_pub", type_="unique")
        batch.create_unique_constraint(
            "uq_awg_notes_server_proto_pub",
            ["server_id", "protocol", "public_key"],
        )


def downgrade() -> None:
    with op.batch_alter_table("awg_notes", schema=None) as batch:
        batch.drop_constraint("uq_awg_notes_server_proto_pub", type_="unique")
        batch.create_unique_constraint(
            "uq_awg_notes_server_pub", ["server_id", "public_key"]
        )
        batch.drop_column("protocol")
