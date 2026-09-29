"""Baseline: the run store as ``Base.metadata.create_all`` built it.

This revision adds nothing that was not already there. A database created by an earlier
``create_all`` is already at this point, so bring it under alembic with
``alembic stamp 0001`` and then ``alembic upgrade head``; a fresh database gets the whole
schema from ``alembic upgrade head`` alone.

Revision ID: 0001
Revises:
Create Date: 2026-09-29
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0001'
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('batches',
    sa.Column('id', sa.String(length=64), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('source_kind', sa.String(length=32), nullable=False),
    sa.Column('label', sa.String(length=256), nullable=False),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('workflow_id', sa.String(length=255), nullable=True),
    sa.Column('finding_count', sa.Integer(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('eval_experiments',
    sa.Column('id', sa.String(length=64), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('agent', sa.String(length=48), nullable=False),
    sa.Column('dataset', sa.String(length=128), nullable=False),
    sa.Column('dataset_version', sa.String(length=32), nullable=False),
    sa.Column('git_sha', sa.String(length=40), nullable=False),
    sa.Column('overlay', sa.String(length=256), nullable=False),
    sa.Column('config_hash', sa.String(length=32), nullable=False),
    sa.Column('repetitions', sa.Integer(), nullable=False),
    sa.Column('metrics', sa.JSON(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('eval_experiments', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_eval_experiments_agent'), ['agent'], unique=False)

    op.create_table('eval_case_results',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('experiment_id', sa.String(length=64), nullable=False),
    sa.Column('case_name', sa.String(length=128), nullable=False),
    sa.Column('repetition', sa.Integer(), nullable=False),
    sa.Column('passed', sa.Boolean(), nullable=False),
    sa.Column('scores', sa.JSON(), nullable=False),
    sa.Column('cost_usd', sa.Float(), nullable=False),
    sa.Column('latency_s', sa.Float(), nullable=False),
    sa.ForeignKeyConstraint(['experiment_id'], ['eval_experiments.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('eval_case_results', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_eval_case_results_experiment_id'), ['experiment_id'], unique=False)

    op.create_table('triage_runs',
    sa.Column('id', sa.String(length=64), nullable=False),
    sa.Column('batch_id', sa.String(length=64), nullable=False),
    sa.Column('fingerprint', sa.String(length=64), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('repo_url', sa.Text(), nullable=False),
    sa.Column('revision', sa.String(length=255), nullable=False),
    sa.Column('title', sa.Text(), nullable=False),
    sa.Column('cwe', sa.String(length=32), nullable=True),
    sa.Column('severity', sa.String(length=16), nullable=False),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('verdict', sa.String(length=32), nullable=True),
    sa.Column('confidence', sa.Float(), nullable=True),
    sa.Column('inconclusive_reason', sa.String(length=48), nullable=True),
    sa.Column('priority', sa.String(length=4), nullable=True),
    sa.Column('priority_score', sa.Float(), nullable=True),
    sa.Column('environment_scope', sa.String(length=16), nullable=False),
    sa.Column('early_exit', sa.String(length=48), nullable=True),
    sa.Column('finding', sa.JSON(), nullable=False),
    sa.Column('result', sa.JSON(), nullable=True),
    sa.Column('cost_usd', sa.Float(), nullable=False),
    sa.Column('total_tokens', sa.Integer(), nullable=False),
    sa.Column('cache_read_tokens', sa.Integer(), nullable=False),
    sa.Column('latency_s', sa.Float(), nullable=False),
    sa.ForeignKeyConstraint(['batch_id'], ['batches.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('batch_id', 'fingerprint', name='uq_batch_fingerprint')
    )
    with op.batch_alter_table('triage_runs', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_triage_runs_fingerprint'), ['fingerprint'], unique=False)
        batch_op.create_index(batch_op.f('ix_triage_runs_priority'), ['priority'], unique=False)
        batch_op.create_index(batch_op.f('ix_triage_runs_verdict'), ['verdict'], unique=False)

    op.create_table('ado_sync',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('run_id', sa.String(length=64), nullable=False),
    sa.Column('work_item_id', sa.Integer(), nullable=False),
    sa.Column('comment_id', sa.Integer(), nullable=True),
    sa.Column('payload_hash', sa.String(length=64), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['run_id'], ['triage_runs.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('run_id')
    )
    op.create_table('agent_invocations',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('run_id', sa.String(length=64), nullable=False),
    sa.Column('seq', sa.Integer(), nullable=False),
    sa.Column('agent', sa.String(length=48), nullable=False),
    sa.Column('model_name', sa.String(length=128), nullable=False),
    sa.Column('config_hash', sa.String(length=32), nullable=False),
    sa.Column('input_tokens', sa.Integer(), nullable=False),
    sa.Column('output_tokens', sa.Integer(), nullable=False),
    sa.Column('cache_read_tokens', sa.Integer(), nullable=False),
    sa.Column('cache_write_tokens', sa.Integer(), nullable=False),
    sa.Column('cost_usd', sa.Float(), nullable=True),
    sa.Column('cost_estimated', sa.Boolean(), nullable=False),
    sa.Column('latency_s', sa.Float(), nullable=False),
    sa.Column('tools_called', sa.JSON(), nullable=False),
    sa.Column('skills_loaded', sa.JSON(), nullable=False),
    sa.ForeignKeyConstraint(['run_id'], ['triage_runs.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('agent_invocations', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_agent_invocations_agent'), ['agent'], unique=False)
        batch_op.create_index(batch_op.f('ix_agent_invocations_run_id'), ['run_id'], unique=False)

    op.create_table('verdict_reviews',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('run_id', sa.String(length=64), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('reviewer', sa.String(length=128), nullable=False),
    sa.Column('decision', sa.String(length=16), nullable=False),
    sa.Column('override_label', sa.String(length=32), nullable=True),
    sa.Column('reason', sa.Text(), nullable=False),
    sa.ForeignKeyConstraint(['run_id'], ['triage_runs.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('run_id')
    )


def downgrade() -> None:
    op.drop_table('verdict_reviews')
    with op.batch_alter_table('agent_invocations', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_agent_invocations_run_id'))
        batch_op.drop_index(batch_op.f('ix_agent_invocations_agent'))

    op.drop_table('agent_invocations')
    op.drop_table('ado_sync')
    with op.batch_alter_table('triage_runs', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_triage_runs_verdict'))
        batch_op.drop_index(batch_op.f('ix_triage_runs_priority'))
        batch_op.drop_index(batch_op.f('ix_triage_runs_fingerprint'))

    op.drop_table('triage_runs')
    with op.batch_alter_table('eval_case_results', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_eval_case_results_experiment_id'))

    op.drop_table('eval_case_results')
    with op.batch_alter_table('eval_experiments', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_eval_experiments_agent'))

    op.drop_table('eval_experiments')
    op.drop_table('batches')
