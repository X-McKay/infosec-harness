"""Alembic environment for the run store (§9).

The URL comes from the app's own ``Settings``, so a migration and the harness that reads
the migrated tables can never point at different databases. Both URLs the project uses —
``postgresql+asyncpg`` in deployment, ``sqlite+aiosqlite`` in tests and CI — are async
drivers, so the online path drives a real async engine and runs the migrations through
``run_sync``. SQLite gets batch mode, since it cannot ALTER a column in place.
"""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import create_async_engine

from infosec_harness.persistence.db import Base, database_connect_args
from infosec_harness.settings import get_settings

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _url() -> str:
    """``-x url=...`` wins (a dump, a scratch database), then an explicitly configured URL,
    then the app's own setting — which is the case that keeps the two in step."""
    return (context.get_x_argument(as_dictionary=True).get("url")
            or config.get_main_option("sqlalchemy.url")
            or get_settings().database_url)


def _configure(**kwargs) -> None:
    context.configure(target_metadata=target_metadata, compare_type=True,
                      compare_server_default=True, **kwargs)


def run_migrations_offline() -> None:
    """Emit SQL to stdout instead of running it — for a DBA-applied change."""
    _configure(url=_url(), literal_binds=True, dialect_opts={"paramstyle": "named"})
    with context.begin_transaction():
        context.run_migrations()


def _run_sync(connection) -> None:
    _configure(connection=connection, render_as_batch=connection.dialect.name == "sqlite")
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    url = _url()
    engine = create_async_engine(url, poolclass=pool.NullPool, connect_args=database_connect_args(url))
    try:
        async with engine.connect() as connection:
            await connection.run_sync(_run_sync)
    finally:
        await engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
