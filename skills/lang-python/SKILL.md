---
name: lang-python
description: "Conventions for reading Python repos: layout, entry points, and test discovery."
---

# Python repositories

- **Manifests:** `pyproject.toml` (PEP 621 / poetry / hatch), `requirements*.txt`, `setup.py`,
  `Pipfile`. Lockfiles: `poetry.lock`, `uv.lock`, `Pipfile.lock`.
- **Layout:** `src/<pkg>/` or a top-level `<pkg>/`. Import paths follow the package dir.
- **Entry points:** WSGI/ASGI apps (Flask `app`, FastAPI/Starlette routes), `argparse`/`click`
  CLIs, Celery tasks, `if __name__ == "__main__"`.
- **Tests:** `tests/`, files `test_*.py` or `*_test.py`, functions `test_*`. Framework is
  usually pytest; `unittest.TestCase` classes are common too.
- **Sinks to note:** `subprocess`/`os.system`, `cursor.execute`, `open`, `eval`/`exec`,
  `pickle`/`yaml.load`, template `| safe` / `Markup`, `requests`/`urllib` with dynamic URLs.
