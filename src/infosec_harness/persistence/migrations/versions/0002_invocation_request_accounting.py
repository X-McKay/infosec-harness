"""Record per-invocation request accounting on agent_invocations.

``AgentOutcome`` already carries ``requests`` and ``repeated_tool_calls``, but the run
store dropped both on the way to the database, so a ``request_limit`` breach could not be
attributed to an agent after the fact — which is the point of persisting the trajectory
at all.

Both columns are added with a server default so the ALTER succeeds on a table that
already has rows; the default is then dropped, because the application supplies a value on
every insert and a lingering default would drift from the model.

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-29
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0002'
down_revision: str | None = '0001'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table('agent_invocations', schema=None) as batch_op:
        batch_op.add_column(sa.Column('requests', sa.Integer(), nullable=False,
                                      server_default=sa.text('0')))
        batch_op.add_column(sa.Column('repeated_tool_calls', sa.JSON(), nullable=False,
                                      server_default=sa.text("'{}'")))
    with op.batch_alter_table('agent_invocations', schema=None) as batch_op:
        batch_op.alter_column('requests', existing_type=sa.Integer(),
                              existing_nullable=False, server_default=None)
        batch_op.alter_column('repeated_tool_calls', existing_type=sa.JSON(),
                              existing_nullable=False, server_default=None)


def downgrade() -> None:
    with op.batch_alter_table('agent_invocations', schema=None) as batch_op:
        batch_op.drop_column('repeated_tool_calls')
        batch_op.drop_column('requests')
