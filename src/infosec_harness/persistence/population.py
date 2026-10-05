"""Which recorded population a run, batch or experiment belongs to: one predicate each.

A run's population is fixed when it is accepted (``RunTelemetry.population``); a run stored
without telemetry belongs to no population and is returned only by unfiltered reads.
"""
from __future__ import annotations

from sqlalchemy import exists, select

from infosec_harness.persistence import db
from infosec_harness.persistence.run_telemetry import Population, telemetry_field

__all__ = ["Population", "batch_population", "experiment_population", "run_population"]


def run_population(population: Population):
    return telemetry_field("population").as_string() == population


def batch_population(population: Population):
    return exists(select(db.TriageRun.id).where(db.TriageRun.batch_id == db.Batch.id,
                                              run_population(population)))


def experiment_population(population: Population):
    if population == "operational":
        return (db.EvalExperiment.backend.notin_(["", "stub"])
                & ~db.EvalExperiment.model_name.startswith("stub:"))
    return db.EvalExperiment.backend == "stub"
