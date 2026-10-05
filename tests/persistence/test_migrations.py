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

from infosec_harness.persistence.db import (
    Base,
    SchemaNotAtHead,
    _bootstrap,
    alembic_config,
    upgrade_to_head,
)


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


def _bootstrap_sync(path: Path) -> None:
    """Run the startup bootstrap (what ``db.create_all`` runs) against one SQLite file."""
    engine = create_engine(f"sqlite:///{path}")
    try:
        with engine.begin() as conn:
            _bootstrap(conn)
    finally:
        engine.dispose()


def _tables(path: Path) -> set[str]:
    engine = create_engine(f"sqlite:///{path}")
    try:
        return set(inspect(engine).get_table_names())
    finally:
        engine.dispose()


def test_bootstrap_refuses_a_database_behind_head_and_migration_still_succeeds():
    """Regression: bootstrap used to run create_all over a versioned database, creating the
    newest tables early, so the pending migration then failed with "table inference_requests
    already exists". A database behind head must be refused untouched, and migrate must work."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "behind.db"
        command.upgrade(_config(path), "0004")
        before = _tables(path)
        assert "inference_requests" not in before
        with pytest.raises(SchemaNotAtHead, match="harness migrate"):
            _bootstrap_sync(path)
        assert _tables(path) == before
        head = ScriptDirectory.from_config(alembic_config()).get_current_head()
        assert upgrade_to_head(f"sqlite+aiosqlite:///{path}") == head
        assert "inference_requests" in _tables(path)
        _bootstrap_sync(path)  # at head: accepted as is


def test_bootstrap_builds_an_empty_database_at_head():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "fresh.db"
        _bootstrap_sync(path)
        head = ScriptDirectory.from_config(alembic_config()).get_current_head()
        engine = create_engine(f"sqlite:///{path}")
        try:
            with engine.connect() as conn:
                assert MigrationContext.configure(conn).get_current_revision() == head
        finally:
            engine.dispose()
        # Stamped at head, so migration is the no-op it should be.
        assert upgrade_to_head(f"sqlite+aiosqlite:///{path}") == head


def test_bootstrap_refuses_unversioned_tables():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "foreign.db"
        command.upgrade(_config(path), "0001")
        engine = create_engine(f"sqlite:///{path}")
        try:
            with engine.begin() as conn:
                conn.execute(text("DROP TABLE alembic_version"))
        finally:
            engine.dispose()
        with pytest.raises(SchemaNotAtHead, match="no migration version"):
            _bootstrap_sync(path)
