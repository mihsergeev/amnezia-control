"""api_keys.expires_at и api_keys.servers - срок ключа и его серверы

Без них ключ интеграции видел все серверы и все приватные конфиги AWG и
действовал бессрочно. Существующие ключи остаются как были: без срока и на
все серверы.

Revision ID: 0024
Revises: 0023
"""

import sqlalchemy as sa
from alembic import op

revision = "0024"
down_revision = "0023"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "api_keys", sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "api_keys",
        sa.Column("servers", sa.Text(), server_default="", nullable=False),
    )


def downgrade() -> None:
    with op.batch_alter_table("api_keys") as batch:
        batch.drop_column("servers")
        batch.drop_column("expires_at")
