import os
import shutil
import tempfile

os.environ.setdefault("HARNESS_MODEL_MODE", "stub")
os.environ.setdefault("PYDANTIC_AI_NO_BANNER", "1")
# Isolated SQLite DB per test session (no Postgres needed).
_dbfile = os.path.join(tempfile.gettempdir(), "harness_test.db")
if os.path.exists(_dbfile):
    os.remove(_dbfile)
os.environ.setdefault("HARNESS_DATABASE_URL", f"sqlite+aiosqlite:///{_dbfile}")

# Isolated recipe cache per test session. Without this a recipe written by one run silently
# changes the next: prepare skips env-planner on a cache hit, so the trajectory report loses an
# agent and the suite passes or fails depending on what a previous run happened to leave behind.
_recipes = os.path.join(tempfile.gettempdir(), "harness_test_recipes")
shutil.rmtree(_recipes, ignore_errors=True)
os.environ.setdefault("HARNESS_RECIPE_CACHE_DIR", _recipes)
