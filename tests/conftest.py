"""Session-wide test isolation, the gating markers, and the one way to import scripts/.

Isolation fails closed: an ambient live model mode or database URL in the caller's shell never
reaches the suite, and is never silently replaced either -- the session refuses to start, so a
runner that meant to test PostgreSQL or a live backend cannot get a SQLite/stub pass instead.
The only ways in are explicit test-only opt-ins:

- HARNESS_TEST_ALLOW_LIVE=1 keeps an ambient HARNESS_MODEL_MODE (otherwise it must be unset or
  stub, and is forced to stub).
- HARNESS_TEST_DATABASE_URL replaces the per-process SQLite database (qualification runners
  such as scripts/broker_ledger_check.py use it to re-run tests against an isolated database).

Values that do not change what a test proves (recipe cache, reports directory) are forced to
per-process scratch locations regardless of the caller's environment.
"""

import functools
import importlib
import os
import shutil
import sys
import tempfile
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"

# Ambient settings that would change what the suite proves; reported by pytest_configure.
_REFUSED: list[str] = []

if os.environ.get("HARNESS_TEST_ALLOW_LIVE") == "1":
    os.environ.setdefault("HARNESS_MODEL_MODE", "stub")
else:
    if os.environ.get("HARNESS_MODEL_MODE", "stub") != "stub":
        _REFUSED.append(
            f"HARNESS_MODEL_MODE={os.environ['HARNESS_MODEL_MODE']} is set: unset it, or set "
            "HARNESS_TEST_ALLOW_LIVE=1 to run the suite in that mode"
        )
    os.environ["HARNESS_MODEL_MODE"] = "stub"
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
if os.environ.get("HARNESS_TEST_DATABASE_URL"):
    os.environ["HARNESS_DATABASE_URL"] = os.environ["HARNESS_TEST_DATABASE_URL"]
else:
    if os.environ.get("HARNESS_DATABASE_URL"):
        _REFUSED.append(
            "HARNESS_DATABASE_URL is set: unset it, or set HARNESS_TEST_DATABASE_URL to run the "
            "suite against that database"
        )
    os.environ["HARNESS_DATABASE_URL"] = f"sqlite+aiosqlite:///{_dbfile}"

# Isolated recipe cache per test process. Without this a recipe written by one run silently
# changes the next: prepare skips env-planner on a cache hit, so the trajectory report loses an
# agent and the suite passes or fails depending on what a previous run happened to leave behind.
_recipes = os.path.join(_tmp, f"harness_test_recipes_{os.getpid()}")
shutil.rmtree(_recipes, ignore_errors=True)
os.environ["HARNESS_RECIPE_CACHE_DIR"] = _recipes

_reports = os.path.join(_tmp, f"harness_test_reports_{os.getpid()}")
os.environ["HARNESS_REPORTS_DIR"] = _reports


def pytest_configure(config: pytest.Config) -> None:
    if _REFUSED:
        raise pytest.UsageError("refusing ambient settings:\n  " + "\n  ".join(_REFUSED))


def load_script(name: str):
    """Import scripts/<name>.py as the top-level module `name`.

    One mechanism, so a script and the scripts it imports (service_validation imports
    ui_deployment_smoke by name) are the same module
    objects the tests patch. scripts/ is appended, never prepended, so it cannot shadow an
    installed package; a name that resolves elsewhere is an error, not a silent substitution.
    """
    if str(SCRIPTS) not in sys.path:
        sys.path.append(str(SCRIPTS))
    module = importlib.import_module(name)
    origin = Path(module.__file__ or "").resolve()
    if origin != SCRIPTS / f"{name}.py":
        raise ImportError(f"{name} resolved to {origin}, not scripts/{name}.py")
    return module


# --- Gating markers (registered in pyproject.toml) -------------------------------------------

_TEMPORAL_REASON = (
    "Temporal CLI not found (PATH or the pinned .harness/mise install); "
    "./dev --profile offline installs the version pinned in .mise.toml"
)


@functools.cache
def _temporal_cli() -> str | None:
    """The `temporal` executable: on PATH, else the checkout's mise-managed pinned install."""
    found = shutil.which("temporal")
    if found:
        return found
    tools = tomllib.loads((ROOT / ".mise.toml").read_text())["tools"]
    version = tools.get("http:temporal", {}).get("version")
    managed = ROOT / ".harness" / "mise" / "installs" / "http-temporal" / str(version) / "temporal"
    return str(managed) if version and os.access(managed, os.X_OK) else None


def _require_temporal() -> str:
    path = _temporal_cli()
    if path:
        return path
    if os.environ.get("HARNESS_TEST_REQUIRE_TEMPORAL") == "1":
        pytest.fail(f"HARNESS_TEST_REQUIRE_TEMPORAL=1 but {_TEMPORAL_REASON}", pytrace=False)
    pytest.skip(_TEMPORAL_REASON)


@pytest.fixture(autouse=True)
def _approved_local_repo_roots(tmp_path_factory, monkeypatch):
    """Admit the suite's own local sources: temporary trees and the seeded corpus.

    Tests build repositories under pytest's base temp or the system temp directory. Production
    admits no local path unless the operator lists its root; tests that check that gate set
    `local_repo_roots` themselves and override this.
    """
    from infosec_harness.settings import get_settings

    monkeypatch.setattr(
        get_settings(), "local_repo_roots",
        [tmp_path_factory.getbasetemp(), Path(tempfile.gettempdir()), ROOT / "eval-corpus"],
    )


@pytest.fixture
def temporal_cli() -> str:
    """Path for WorkflowEnvironment.start_local(dev_server_existing_path=...)."""
    return _require_temporal()


def pytest_runtest_setup(item: pytest.Item) -> None:
    if item.get_closest_marker("requires_temporal"):
        _require_temporal()
    for marker in item.iter_markers("requires_service"):
        if not marker.args:
            pytest.fail("requires_service needs the environment variable names it gates on")
        missing = [name for name in marker.args if not os.environ.get(name)]
        if missing:
            pytest.skip(
                f"explicit service qualification runner required: {', '.join(missing)} unset"
            )
    if item.get_closest_marker("posix") and os.name != "posix":
        pytest.skip("needs POSIX process semantics")


def pytest_report_header(config: pytest.Config) -> str:
    return (
        f"harness: HARNESS_MODEL_MODE={os.environ['HARNESS_MODEL_MODE']}, "
        f"temporal CLI={_temporal_cli() or 'absent'}"
    )


def pytest_sessionfinish(session, exitstatus):
    """Remove this process's scratch state. Without it, one file per run accumulates in /tmp."""
    for path in (_dbfile, f"{_dbfile}-journal", f"{_dbfile}-wal", f"{_dbfile}-shm"):
        if os.path.exists(path):
            os.remove(path)
    shutil.rmtree(_recipes, ignore_errors=True)
    shutil.rmtree(_reports, ignore_errors=True)
