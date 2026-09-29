"""Add durable submission, progress, evidence and honest measurement metadata.

Legacy measurement metadata is NULL: historical zeroes are not proof of observed usage.
"""
import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table("budget_ledgers",
        sa.Column("root_id", sa.String(64), primary_key=True),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("state", sa.JSON(), nullable=False))
    op.add_column("batches", sa.Column("submission", sa.JSON(), nullable=True))
    for name in ("telemetry", "evidence"):
        op.add_column("triage_runs", sa.Column(name, sa.JSON(), nullable=True))
    op.create_table("run_events",
        sa.Column("id", sa.String(128), primary_key=True),
        sa.Column("run_id", sa.String(64), sa.ForeignKey("triage_runs.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("phase", sa.String(48), nullable=False),
        sa.Column("detail", sa.Text(), nullable=False))
    op.create_index("ix_run_events_run_id", "run_events", ["run_id"])
    op.create_table("review_history",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("run_id", sa.String(64), sa.ForeignKey("triage_runs.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record", sa.JSON(), nullable=False))
    op.create_index("ix_review_history_run_id", "review_history", ["run_id"])


def downgrade() -> None:
    op.drop_table("budget_ledgers")
    op.drop_table("review_history")
    op.drop_table("run_events")
    for name in ("evidence", "telemetry"):
        op.drop_column("triage_runs", name)
    op.drop_column("batches", "submission")
