"""Run telemetry schema 2: one typed record with an accepted population.

Telemetry recorded without a population, acceptance time or phase was never attributable to a
measured population; it becomes NULL (unmeasured), exactly as 0004 recorded runs that predate
measurement metadata. Every other record keeps its declared fields at schema version 2.
"""
import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None

_FIELDS = ("population", "phase", "accepted_at", "updated_at", "completed_at", "wall_time_s",
           "agent_time_s", "cost_usd", "known_cost_usd", "accounting_complete",
           "cost_accounting_complete", "known_tokens", "input_tokens", "output_tokens",
           "cost_coverage", "total_tokens")
_runs = sa.table("triage_runs", sa.column("id", sa.String), sa.column("telemetry", sa.JSON))


def _rewrite(convert) -> None:
    connection = op.get_bind()
    for identity, telemetry in connection.execute(
            sa.select(_runs.c.id, _runs.c.telemetry).where(_runs.c.telemetry.is_not(None))).all():
        converted = convert(telemetry)
        connection.execute(_runs.update().where(_runs.c.id == identity)
                           .values(telemetry=sa.null() if converted is None else converted))


def _upgrade(telemetry: dict) -> dict | None:
    if (not isinstance(telemetry, dict)
            or telemetry.get("population") not in ("operational", "demo")
            or not isinstance(telemetry.get("accepted_at"), str)
            or not isinstance(telemetry.get("phase"), str)):
        return None
    return {"schema_version": 2,
            **{key: telemetry[key] for key in _FIELDS if telemetry.get(key) is not None}}


def upgrade() -> None:
    _rewrite(_upgrade)


def downgrade() -> None:
    _rewrite(lambda telemetry: {**telemetry, "schema_version": 1})
