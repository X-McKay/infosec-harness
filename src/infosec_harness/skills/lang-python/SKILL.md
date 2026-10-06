---
name: lang-python
description: 'Python repositories: layout, entry points, test discovery, common sinks. Use this when the repository is primarily Python.'
metadata:
  owner: appsec
  version: 1.2.0
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

## When the toolchain is absent

The workspace image ships Python 3.12; pytest and third-party packages come from the
repository's declared dependencies through `environment`. Verify with `command -v python3` and
`python3 -c "import <module>"` for each import on the path to the sink. A probe needs no test
runner: a plain script that imports the real code and prints the `HARNESS_PROBE` line is
enough. If a module the target cannot import without is missing and `environment` cannot
provide it, do not stub it. Return `inconclusive`, name the exact missing module as a
limitation in the verdict summary, and record what reading established.

## Completion criteria

- You can name the manifests, the import layout, the entry points, and where tests live.

