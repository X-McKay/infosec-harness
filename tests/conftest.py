import os
import tempfile

os.environ.setdefault("HARNESS_MODEL_MODE", "stub")
os.environ.setdefault("PYDANTIC_AI_NO_BANNER", "1")
# Isolated SQLite DB per test session (no Postgres needed).
_dbfile = os.path.join(tempfile.gettempdir(), "harness_test.db")
if os.path.exists(_dbfile):
    os.remove(_dbfile)
os.environ.setdefault("HARNESS_DATABASE_URL", f"sqlite+aiosqlite:///{_dbfile}")
