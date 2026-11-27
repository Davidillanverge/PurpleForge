"""integration configs (deploy-time credentials configured from the UI)

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-27 10:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "integration_configs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("values", JSON, nullable=False),
        sa.Column("secrets_encrypted", JSON, nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_integration_configs")),
        sa.UniqueConstraint("tenant_id", "name", name=op.f("uq_integration_configs_tenant_id_name")),
    )
    with op.batch_alter_table("integration_configs", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_integration_configs_tenant_id"), ["tenant_id"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("integration_configs", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_integration_configs_tenant_id"))
    op.drop_table("integration_configs")
