set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

# `uv run --locked` is the primary path. Without uv on PATH (put the managed one there with
# `eval "$(./dev env)"`), Python recipes use an already-synced environment instead: this
# checkout's .venv, else the main checkout's when this is a git worktree, with this checkout's
# src/ first on PYTHONPATH. That fallback does not verify the lock.
fallback_venv := `if [ -x .venv/bin/python ]; then echo "$PWD/.venv"; else c="$(git rev-parse --path-format=absolute --git-common-dir 2>/dev/null || true)"; echo "${c%/.git}/.venv"; fi`
python := if `command -v uv >/dev/null 2>&1 && echo uv || echo none` == "uv" { "uv run --locked python" } else { "env PYTHONPATH='" + justfile_directory() / "src" + "' '" + fallback_venv / "bin/python'" }

bootstrap:
    uv sync --locked

check:
    {{python}} -m ruff check src tests scripts deploy/openshell/build_context.py
    {{python}} -m compileall -q src scripts

lint-fix:
    {{python}} -m ruff check src tests scripts deploy/openshell/build_context.py --fix

generated-check:
    {{python}} scripts/check_api_schema.py
    {{python}} scripts/generated.py --check

generated-sync:
    {{python}} scripts/generated.py

regenerate: generated-sync
    {{python}} -c "import json; from pathlib import Path; from infosec_harness.api import app; Path('ui/openapi.json').write_text(json.dumps(app.openapi(), indent=2)+'\n')"
    cd ui && npm run gen:api

test *args:
    {{python}} -m pytest -m "not network" {{args}}

test-network *args:
    {{python}} -m pytest -m network {{args}}

ui-build:
    cd ui && npm ci && npm run build

# Installs the locked UI dependencies first when ui/node_modules is absent (a fresh worktree).
ui-check:
    cd ui && if [ ! -d node_modules ]; then npm ci --no-audit --no-fund; fi
    cd ui && npm run format:check
    cd ui && npm run check:api
    cd ui && npm run build

ui-e2e *args:
    cd ui && npm run e2e -- {{args}}
