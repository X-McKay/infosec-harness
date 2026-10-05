set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

# The code loop. `./dev` owns machine setup and the stack; `harness` is the product and its
# evals. Tool versions come from .mise.toml: `./dev check` and `./dev test` run these recipes
# with the pinned tools; otherwise use `.harness/bin/mise exec -- just <recipe>` after `./dev`.
# Every recipe uses `uv run --locked`: a stale uv.lock fails instead of being rewritten.
# CI calls these same recipes; do not re-type their commands in .github/workflows/ci.yml.

# Install the locked Python dependencies into .venv.
bootstrap:
    uv sync --locked

# Lint (src, tests and scripts), byte-compile, and validate every agent spec.
check:
    uv run --locked ruff check src tests scripts
    uv run --locked python -m compileall -q src scripts
    HARNESS_MODEL_MODE=stub uv run --locked harness agents validate

# Apply ruff's automatic fixes.
lint-fix:
    uv run --locked ruff check src tests scripts --fix

# Generated-file drift (the OpenAPI document), without rewriting the checkout.
generated-check:
    HARNESS_MODEL_MODE=stub uv run --locked python scripts/check_api_schema.py

# Regenerate every generated file: the agent JSON schema, the OpenAPI document, the UI client.
regenerate:
    HARNESS_MODEL_MODE=stub uv run --locked harness agents schema
    HARNESS_MODEL_MODE=stub uv run --locked python -c "import json,infosec_harness.api.app as a; open('ui/openapi.json','w').write(json.dumps(a.app.openapi(),indent=2))"
    cd ui && npm run gen:api

# The deterministic suite on stub models, excluding tests marked `network` (PyPI/GitHub).
test *args:
    HARNESS_MODEL_MODE=stub uv run --locked pytest -m "not network" {{args}}

# Only the network-marked tests (CI runs these as their own step).
test-network *args:
    HARNESS_MODEL_MODE=stub uv run --locked pytest -m network {{args}}

# Every test, network-marked ones included.
test-all *args:
    HARNESS_MODEL_MODE=stub uv run --locked pytest {{args}}

# Every agent's eval dataset on stub models, as CI runs it: proves datasets and adapters, not quality.
eval *args:
    HARNESS_MODEL_MODE=stub uv run --locked harness eval run --all {{args}}

# Offline cost measurements: model round trips, prompt-cache prefix stability, batch schedule.
measure:
    HARNESS_MODEL_MODE=stub uv run --locked python scripts/measure_exploration.py
    HARNESS_MODEL_MODE=stub uv run --locked python scripts/measure_cache_prefix.py
    HARNESS_MODEL_MODE=stub uv run --locked python scripts/measure_batch_schedule.py

# Agent / Multi-Agent Playbook conformance via agentctl (installed, or pass its project path).
conformance agentctl="":
    uv run --locked python scripts/conformance.py {{ if agentctl != "" { "--agentctl " + quote(agentctl) } else { "" } }}

# Install UI dependencies and build the production bundle.
ui-build:
    cd ui && npm ci && npm run build

# UI formatting, generated-client drift, and the type-checked production build.
ui-check:
    cd ui && npm run format:check
    cd ui && npm run check:api
    cd ui && npm run build

# Read-only checks against configured services; pass --model to authorize one inference.
validate-services *args:
    uv run --locked python scripts/service_validation.py {{args}}
