"""The migrations build exactly the schema the models declare, and nothing drifts.

``create_all`` is the bootstrap path (tests, CI, a fresh local database) and
``alembic upgrade head`` is the deployment path. They must produce the same schema, or a
run that works locally breaks against a migrated Postgres. These tests run the real
migrations against a throwaway SQLite database and compare the result to the models.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text

from infosec_harness.persistence.db import Base, alembic_config, upgrade_to_head


def _config(db_path: Path):
    # An explicit URL keeps these migrations off the database the rest of the suite uses.
    cfg = alembic_config()
    cfg.set_main_option("sqlalchemy.url", f"sqlite+aiosqlite:///{db_path}")
    return cfg


@pytest.fixture
def migrated_db():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "migrated.db"
        command.upgrade(_config(path), "head")
        yield path


def test_upgrade_head_matches_the_models(migrated_db):
    """`alembic upgrade head` leaves no difference against Base.metadata."""
    engine = create_engine(f"sqlite:///{migrated_db}")
    try:
        with engine.connect() as conn:
            ctx = MigrationContext.configure(conn, opts={"compare_type": True})
            diff = compare_metadata(ctx, Base.metadata)
    finally:
        engine.dispose()
    assert diff == [], f"migrations have drifted from the models: {diff}"


def test_request_accounting_columns_are_migrated(migrated_db):
    """The columns a request_limit breach is diagnosed from reach the database."""
    engine = create_engine(f"sqlite:///{migrated_db}")
    try:
        columns = {c["name"] for c in inspect(engine).get_columns("agent_invocations")}
    finally:
        engine.dispose()
    assert {"requests", "repeated_tool_calls"} <= columns


def test_downgrade_returns_to_the_baseline(migrated_db):
    """Every revision is reversible, so a bad deploy can be rolled back."""
    cfg = _config(migrated_db)
    command.downgrade(cfg, "base")
    engine = create_engine(f"sqlite:///{migrated_db}")
    try:
        tables = set(inspect(engine).get_table_names())
    finally:
        engine.dispose()
    assert tables <= {"alembic_version"}, f"downgrade left tables behind: {tables}"


def test_upgrade_adopts_a_pre_alembic_database():
    """A database built by the old `create_all` has no version row. It must still be able
    to pick up later revisions, or a deployed harness can never gain a column."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "legacy.db"
        # Revision 0001 *is* what the old create_all produced; dropping the version table
        # leaves exactly the database a deployment has today.
        command.upgrade(_config(path), "0001")
        engine = create_engine(f"sqlite:///{path}")
        try:
            with engine.begin() as conn:
                conn.execute(text("DROP TABLE alembic_version"))
        finally:
            engine.dispose()

        head = ScriptDirectory.from_config(alembic_config()).get_current_head()
        assert upgrade_to_head(f"sqlite+aiosqlite:///{path}") == head

        engine = create_engine(f"sqlite:///{path}")
        try:
            columns = {c["name"] for c in inspect(engine).get_columns("agent_invocations")}
        finally:
            engine.dispose()
        assert {"requests", "repeated_tool_calls"} <= columns
