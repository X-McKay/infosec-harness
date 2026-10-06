---
name: lang-python
description: 'Conventions for reading Python repositories: layout, entry points, test discovery, and
  common sinks. Use this when the repository is primarily Python.'
metadata:
  owner: appsec
  version: 1.1.0
---

# Python repositories

## Use this skill when

- The repository's primary language is Python.
- You need to locate its entry points, tests, or import paths.

## Do not use this skill when

- The repository is primarily another language; load that `lang-*` skill instead.
- You are planning install or build commands — use `environment`.

## Procedure

- **Manifests:** `pyproject.toml` (PEP 621 / poetry / hatch), `requirements*.txt`, `setup.py`,
  `Pipfile`. Lockfiles: `poetry.lock`, `uv.lock`, `Pipfile.lock`.
- **Layout:** `src/<pkg>/` or a top-level `<pkg>/`. Import paths follow the package dir.
- **Entry points:** WSGI/ASGI apps (Flask `app`, FastAPI/Starlette routes), `argparse`/`click`
  CLIs, Celery tasks, `if __name__ == "__main__"`.
- **Tests:** `tests/`, files `test_*.py` or `*_test.py`, functions `test_*`. Framework is
  usually pytest; `unittest.TestCase` classes are common too.
- **Sinks to note:** `subprocess`/`os.system`, `cursor.execute`, `open`, `eval`/`exec`,
  `pickle`/`yaml.load`, template `| safe` / `Markup`, `requests`/`urllib` with dynamic URLs.

## Completion criteria

- You can name the manifests, the import layout, the entry points, and where tests live.

