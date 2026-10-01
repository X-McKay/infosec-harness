import os
import shutil
import tempfile

os.environ.setdefault("HARNESS_MODEL_MODE", "stub")
os.environ.setdefault("PYDANTIC_AI_NO_BANNER", "1")
# Isolated SQLite DB per test *process* (no Postgres needed).
#
# The pid is not decoration. These paths used to be fixed, which is fine for one run and wrong
# the moment there are two: a second pytest on the same machine deleted the first one's database
# out from under its open connections, and the first then failed with SQLite's "attempt to write
# a readonly database" -- in a *different* test file from the one that had been writing. The
# result looked exactly like a schema bug in whatever had most recently changed, and cost real
# time to chase before the concurrent run was noticed. Concurrent sessions and worktrees are
# normal here, so the isolation has to be real rather than assumed.
_tmp = tempfile.gettempdir()
_dbfile = os.path.join(_tmp, f"harness_test_{os.getpid()}.db")
if os.path.exists(_dbfile):
    os.remove(_dbfile)
os.environ.setdefault("HARNESS_DATABASE_URL", f"sqlite+aiosqlite:///{_dbfile}")

# Isolated recipe cache per test process. Without this a recipe written by one run silently
# changes the next: prepare skips env-planner on a cache hit, so the trajectory report loses an
# agent and the suite passes or fails depending on what a previous run happened to leave behind.
_recipes = os.path.join(_tmp, f"harness_test_recipes_{os.getpid()}")
shutil.rmtree(_recipes, ignore_errors=True)
os.environ.setdefault("HARNESS_RECIPE_CACHE_DIR", _recipes)

_reports = os.path.join(_tmp, f"harness_test_reports_{os.getpid()}")
os.environ.setdefault("HARNESS_REPORTS_DIR", _reports)


def pytest_sessionfinish(session, exitstatus):
    """Remove this process's scratch state. Without it, one file per run accumulates in /tmp."""
    for path in (_dbfile, f"{_dbfile}-journal", f"{_dbfile}-wal", f"{_dbfile}-shm"):
        if os.path.exists(path):
            os.remove(path)
    shutil.rmtree(_recipes, ignore_errors=True)
    shutil.rmtree(_reports, ignore_errors=True)
