"""Population predicates shared by operational observation routes."""
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


def operational_experiment():
    return (db.EvalExperiment.backend.notin_(["", "stub"]) &
            ~db.EvalExperiment.model_name.startswith("stub:"))
