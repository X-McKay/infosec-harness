set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

# --- Local development (host) ---
bootstrap:
    uv sync --all-extras

check:
    uv run ruff check src tests
    uv run python -m compileall -q src
    HARNESS_MODEL_MODE=stub uv run harness agents validate

test:
    HARNESS_MODEL_MODE=stub uv run pytest

lint-fix:
    uv run ruff check src tests --fix

# What a run costs in model round trips, prompt-cache prefix stability, and batch schedule.
# All three are offline: no provider, no container, no credentials, seconds to run. Use them
# before changing a read tool, a prompt's exploration procedure, or per-repo concurrency.
measure:
    HARNESS_MODEL_MODE=stub uv run python scripts/measure_exploration.py
    HARNESS_MODEL_MODE=stub uv run python scripts/measure_cache_prefix.py
    HARNESS_MODEL_MODE=stub uv run python scripts/measure_batch_schedule.py

# Conformance against the Agent / Multi-Agent Playbooks, via agentctl.
# Needs agentctl: `uv tool install ./tools/agentctl` from the playbooks repo, or
# `just conformance AGENTCTL=/path/to/playbooks` to use a checkout.
conformance agentctl="":
    uv run python scripts/conformance.py {{ if agentctl != "" { "--agentctl " + agentctl } else { "" } }}

# Regenerate every derived governance artifact from its source of truth.
governance:
    uv run python scripts/gen_risk_assessments.py
    uv run python scripts/gen_release_policies.py
    uv run python scripts/gen_system_spec.py
    uv run python scripts/restructure_skills.py

# Regenerate the agent-spec JSON schema and the web OpenAPI client.
agents-schema:
    HARNESS_MODEL_MODE=stub uv run harness agents schema

openapi:
    HARNESS_MODEL_MODE=stub uv run python -c "import json,infosec_harness.api.app as a; open('web/openapi.json','w').write(json.dumps(a.app.openapi(),indent=2))"
    cd web && npm run gen:api

# --- Offline demo (no Temporal, no Docker): full pipeline with stub models ---
demo findings="examples/findings.sample.json":
    HARNESS_MODEL_MODE=stub HARNESS_DATABASE_URL="sqlite+aiosqlite:///.harness/demo.db" \
      uv run harness submit {{findings}} --local --label demo

# --- Evals ---
eval-run agent="probe-diagnosis":
    HARNESS_MODEL_MODE=stub HARNESS_DATABASE_URL="sqlite+aiosqlite:///.harness/demo.db" \
      uv run harness eval run {{agent}}

# Every agent's dataset through its adapter, on the stub model — what CI runs. This proves the
# datasets and adapters still load and score end to end; stub accuracy is meaningless and low,
# so read nothing into the numbers.
eval-adapters:
    mkdir -p .harness
    for dataset in src/infosec_harness/agents/*/evals/dataset.yaml; do \
      agent="$(basename "$(dirname "$(dirname "$dataset")")")"; \
      echo "--- $agent"; \
      HARNESS_MODEL_MODE=stub HARNESS_DATABASE_URL="sqlite+aiosqlite:///.harness/demo.db" \
        uv run harness eval run "$agent"; \
    done

# One agent's dataset against several models, printed side by side: accuracy, latency, cost.
# Sequential on purpose — latency is one of the things being measured.
eval-models agent="verdict" models="sonnet opus haiku":
    uv run harness eval run {{agent}} {{ prepend("-m ", models) }}

# Every stored experiment, newest first, with the model and the commit each measured.
eval-results:
    uv run harness eval results

# Record an experiment as the committed baseline for its agent and model.
eval-baseline experiment:
    uv run harness eval baseline save {{experiment}}

# --- Full stack ---
up:
    docker compose up --build

down:
    docker compose down -v

worker:
    uv run harness worker

api:
    uv run harness api

web-build:
    cd web && npm install && npm run build
