set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

# Tool versions come from .mise.toml. `./dev check` and `./dev test` run these recipes with the
# pinned tools; otherwise use `.harness/bin/mise exec -- just <recipe>` after `./dev`.
# Every recipe uses `uv run --locked`: a stale uv.lock fails instead of being rewritten.
# CI calls these same recipes; do not re-type their commands in .github/workflows/ci.yml.

# --- Local development (host) ---
bootstrap:
    uv sync --locked

# Lint (src, tests and scripts), byte-compile, and validate every agent spec.
check:
    uv run --locked ruff check src tests scripts
    uv run --locked python -m compileall -q src scripts
    HARNESS_MODEL_MODE=stub uv run --locked harness agents validate

lint-fix:
    uv run --locked ruff check src tests scripts --fix

# The only generated artifact: the OpenAPI document the UI client is built from. Checked
# without rewriting the checkout; `just openapi` regenerates it.
generated-check:
    HARNESS_MODEL_MODE=stub uv run --locked python scripts/check_api_schema.py

# The deterministic suite: everything except tests marked `network` (they install from PyPI).
# Tests marked `requires_temporal` skip with a reason when the pinned Temporal CLI is absent;
# HARNESS_TEST_REQUIRE_TEMPORAL=1 (set by ./dev test and CI) makes that a failure instead.
test *args:
    HARNESS_MODEL_MODE=stub uv run --locked pytest -m "not network" {{args}}

# Only the network-marked tests (CI runs these as their own step).
test-network *args:
    HARNESS_MODEL_MODE=stub uv run --locked pytest -m network {{args}}

# Every test, network-marked ones included.
test-all *args:
    HARNESS_MODEL_MODE=stub uv run --locked pytest {{args}}

# What a run costs in model round trips, prompt-cache prefix stability, and batch schedule.
# All three are offline: no provider, no container, no credentials, seconds to run. Use them
# before changing a read tool, a prompt's exploration procedure, or per-repo concurrency.
measure:
    HARNESS_MODEL_MODE=stub uv run --locked python scripts/measure_exploration.py
    HARNESS_MODEL_MODE=stub uv run --locked python scripts/measure_cache_prefix.py
    HARNESS_MODEL_MODE=stub uv run --locked python scripts/measure_batch_schedule.py

# Conformance against the Agent / Multi-Agent Playbooks, via agentctl.
# Needs agentctl: `uv tool install ./tools/agentctl` from the playbooks repo, or pass the
# agentctl project as the argument: `just conformance /path/to/playbooks/tools/agentctl`.
conformance agentctl="":
    uv run --locked python scripts/conformance.py {{ if agentctl != "" { "--agentctl " + quote(agentctl) } else { "" } }}

# Regenerate the agent-spec JSON schema and the web OpenAPI client.
agents-schema:
    HARNESS_MODEL_MODE=stub uv run --locked harness agents schema

openapi:
    HARNESS_MODEL_MODE=stub uv run --locked python -c "import json,infosec_harness.api.app as a; open('ui/openapi.json','w').write(json.dumps(a.app.openapi(),indent=2))"
    cd ui && npm run gen:api

# --- Offline demo (no Temporal, no Docker): full pipeline with stub models ---
demo findings="examples/findings.sample.json":
    HARNESS_MODEL_MODE=stub HARNESS_DATABASE_URL="sqlite+aiosqlite:///.harness/demo.db" \
      uv run --locked harness submit {{findings}} --local --label demo

# Upgrade the demo database to the latest revision (adopts one built before migrations existed).
migrate:
    HARNESS_MODEL_MODE=stub HARNESS_DATABASE_URL="sqlite+aiosqlite:///.harness/demo.db" \
      uv run --locked harness migrate

# --- Evals ---
eval-run agent="probe-diagnosis":
    HARNESS_MODEL_MODE=stub HARNESS_DATABASE_URL="sqlite+aiosqlite:///.harness/demo.db" \
      uv run --locked harness eval run {{agent}}

# Every agent's dataset through its adapter, on the stub model — what CI runs. This proves the
# datasets and adapters still load and score end to end; stub accuracy is meaningless and low,
# so read nothing into the numbers. A dataset that stops parsing, an adapter whose unpacking
# drifts from its agent's output type, or a renamed field fails the run. An empty glob fails
# too: zero datasets would otherwise read as zero failures.
eval-adapters:
    #!/usr/bin/env bash
    set -euo pipefail
    shopt -s nullglob
    datasets=(src/infosec_harness/agents/*/evals/dataset.yaml)
    if [ ${#datasets[@]} -eq 0 ]; then
      echo "no src/infosec_harness/agents/*/evals/dataset.yaml found - adapter coverage would be silently empty" >&2
      exit 1
    fi
    mkdir -p .harness
    for dataset in "${datasets[@]}"; do
      agent="$(basename "$(dirname "$(dirname "$dataset")")")"
      echo "--- $agent"
      HARNESS_MODEL_MODE=stub HARNESS_DATABASE_URL="sqlite+aiosqlite:///.harness/demo.db" \
        uv run --locked harness eval run "$agent"
    done

# One agent's dataset against several models, printed side by side: accuracy, latency, cost.
# Sequential on purpose — latency is one of the things being measured.
eval-models agent="verdict" models="sonnet opus haiku":
    uv run --locked harness eval run {{agent}} {{ prepend("-m ", models) }}

# Every stored experiment, newest first, with the model and the commit each measured.
eval-results:
    uv run --locked harness eval results

# Record an experiment as the committed baseline for its agent and model.
eval-baseline experiment:
    uv run --locked harness eval baseline save {{experiment}}

# --- UI ---
ui-build:
    cd ui && npm ci && npm run build

# Handwritten frontend formatting, generated-client drift, and type/production checks.
ui-check:
    cd ui && npm run format:check
    cd ui && npm run check:api
    cd ui && npm run build

# --- Services ---
# Read-only deployment/service checks; add --model to explicitly request inference.
# Uses the configured HARNESS_ENV_FILE/settings for local or hosted services. The managed
# stack is ./dev's (./dev, ./dev stop, ./dev reset); there are no host-compose recipes.
validate-services *args:
    uv run --locked python scripts/service_validation.py {{args}}
