"""Add controller-owned credential broker request fences without altering old roots."""
import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table("inference_requests",
        sa.Column("request_id", sa.String(64), primary_key=True),
        sa.Column("root_id", sa.String(64), sa.ForeignKey("budget_ledgers.root_id"), nullable=False),
        sa.Column("operation_id", sa.String(512), nullable=False),
        sa.Column("lease_id", sa.String(128), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("request", sa.JSON(), nullable=False),
        sa.Column("allocation", sa.JSON(), nullable=False),
        sa.Column("overrun", sa.JSON(), nullable=True),
        sa.Column("fence", sa.String(128), nullable=True),
        sa.Column("result", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_inference_requests_root_id", "inference_requests", ["root_id"])


def downgrade() -> None:
    op.drop_index("ix_inference_requests_root_id", table_name="inference_requests")
    op.drop_table("inference_requests")
