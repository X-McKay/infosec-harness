"""Record which code and which model an eval experiment measured.

``eval_experiments`` gained ``git_dirty``, ``harness_version`` and the resolved model
(``model_tier``, ``model_name``, ``backend``, ``pricing``) as their own columns, so runs can
be grouped and compared by model rather than only by an opaque ``config_hash``.

Added with server defaults so the ALTER succeeds on populated tables, then the defaults are
dropped: the application supplies every value, and a lingering default would drift from
the model. Existing rows read as "unknown", which is the truth about them.

Revision ID: 0003
Revises: 0002
Create Date: 2026-09-29
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0003'
down_revision: str | None = '0002'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_STRINGS = (('harness_version', 32), ('model_tier', 32), ('model_name', 128),
            ('backend', 32), ('pricing', 16))


def upgrade() -> None:
    with op.batch_alter_table('eval_experiments', schema=None) as batch_op:
        batch_op.add_column(sa.Column('git_dirty', sa.Boolean(), nullable=False,
                                      server_default=sa.false()))
        for name, length in _STRINGS:
            batch_op.add_column(sa.Column(name, sa.String(length=length), nullable=False,
                                          server_default=''))
        batch_op.create_index(batch_op.f('ix_eval_experiments_model_name'), ['model_name'], unique=False)
        batch_op.create_index(batch_op.f('ix_eval_experiments_model_tier'), ['model_tier'], unique=False)
    with op.batch_alter_table('eval_experiments', schema=None) as batch_op:
        batch_op.alter_column('git_dirty', existing_type=sa.Boolean(), existing_nullable=False,
                              server_default=None)
        for name, length in _STRINGS:
            batch_op.alter_column(name, existing_type=sa.String(length=length),
                                  existing_nullable=False, server_default=None)


def downgrade() -> None:
    with op.batch_alter_table('eval_experiments', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_eval_experiments_model_tier'))
        batch_op.drop_index(batch_op.f('ix_eval_experiments_model_name'))
        for name, _ in reversed(_STRINGS):
            batch_op.drop_column(name)
        batch_op.drop_column('git_dirty')
