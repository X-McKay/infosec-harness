set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

bootstrap:
    uv sync --locked

check:
    uv run --locked ruff check src tests scripts deploy/openshell/build_context.py
    uv run --locked python -m compileall -q src scripts

lint-fix:
    uv run --locked ruff check src tests scripts deploy/openshell/build_context.py --fix

generated-check:
    uv run --locked python scripts/check_api_schema.py
    uv run --locked python scripts/generated.py --check

generated-sync:
    uv run --locked python scripts/generated.py

regenerate: generated-sync
    uv run --locked python -c "import json; from pathlib import Path; from infosec_harness.web import app; Path('ui/openapi.json').write_text(json.dumps(app.openapi(), indent=2)+'\n')"
    cd ui && npm run gen:api

test *args:
    uv run --locked pytest -m "not network" {{args}}

test-network *args:
    uv run --locked pytest -m network {{args}}

ui-build:
    cd ui && npm ci && npm run build

ui-check:
    cd ui && npm run format:check
    cd ui && npm run check:api
    cd ui && npm run build
