"""Which recorded population a run, batch or experiment belongs to: one predicate each.

``legacy`` is data recorded without measurement metadata (no ``telemetry.population``), kept
apart so it never mixes with operational or demo measurements.
"""
from __future__ import annotations

from typing import Literal

from sqlalchemy import exists, select

from infosec_harness.persistence import db

Population = Literal["operational", "demo", "legacy"]


def run_population(population: Population):
    value = db.TriageRun.telemetry["population"].as_string()
    return value.is_(None) if population == "legacy" else value == population


def batch_population(population: Population):
    return exists(select(db.TriageRun.id).where(db.TriageRun.batch_id == db.Batch.id,
                                              run_population(population)))


def experiment_population(population: Population):
    if population == "operational":
        return (db.EvalExperiment.backend.notin_(["", "stub"])
                & ~db.EvalExperiment.model_name.startswith("stub:"))
    if population == "demo":
        return db.EvalExperiment.backend == "stub"
    return db.EvalExperiment.backend == ""


def recorded_population(telemetry: dict | None) -> Population:
    """The population of one loaded run, by the same rule as :func:`run_population`."""
    value = (telemetry or {}).get("population")
    return value if value in ("operational", "demo") else "legacy"
