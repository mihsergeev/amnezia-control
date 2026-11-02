"""Allow several cascade entries to use one exit.

Revision ID: 0032
Revises: 0031
"""

import json

import sqlalchemy as sa
from alembic import op

revision = "0032"
down_revision = "0031"
branch_labels = None
depends_on = None


def upgrade() -> None:
    constraints = sa.inspect(op.get_bind()).get_unique_constraints("cascades")
    names = [c["name"] or "uq_cascades_exit_server_id" for c in constraints
             if c["column_names"] == ["exit_server_id"]]
    with op.batch_alter_table("cascades", naming_convention={
        "uq": "uq_%(table_name)s_%(column_0_name)s",
    }) as batch:
        for name in names:
            batch.drop_constraint(name, type_="unique")


def downgrade() -> None:
    for raw in op.get_bind().execute(sa.text("SELECT params FROM cascades")).scalars():
        if json.loads(raw or "{}").get("runtime_layout") in (2, "2"):
            raise RuntimeError("Remove layout-2 cascades before downgrading the panel")
    duplicate = op.get_bind().execute(sa.text(
        "SELECT exit_server_id FROM cascades GROUP BY exit_server_id HAVING COUNT(*) > 1"
    )).first()
    if duplicate is not None:
        raise RuntimeError("Remove shared-exit cascades before downgrading the schema")
    with op.batch_alter_table("cascades") as batch:
        batch.create_unique_constraint("uq_cascades_exit_server_id", ["exit_server_id"])
