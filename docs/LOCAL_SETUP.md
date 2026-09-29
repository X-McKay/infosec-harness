# Local setup

How to run the harness on your own machine, including a live-model run against the test
endpoint. Everything is on the branch `claude/infosec-harness-redesign-0akr9w`.

```bash
git fetch origin
git checkout claude/infosec-harness-redesign-0akr9w
```

## Prerequisites

- Python 3.12 and [`uv`](https://docs.astral.sh/uv/)
- `just` (task runner) — optional but assumed below
- Docker (for the full stack and for real sandboxed builds/probes)
- Node 22 + npm (only for the web app)
- gVisor (`runsc`) for real probe isolation — see [Sandbox](#sandbox-gvisor). Without it,
  builds/probes fail closed unless you set `HARNESS_ALLOW_INSECURE_RUNTIME=true`.

## 1. Offline smoke (no credentials, no Docker)

Proves the code, agent specs, and the whole pipeline with deterministic stub models.

```bash
just bootstrap          # uv sync --all-extras
just check              # ruff + compile + validate all 11 agent specs
just test               # full test suite (stub models, SQLite)
just demo               # run the pipeline in-process on examples/findings.sample.json
```

`just test` should be all green. The Temporal integration test
(`tests/test_workflow_integration.py`) needs the `temporal` CLI on PATH and skips without it:

```bash
uv run pytest tests/test_workflow_integration.py
```

It was previously believed to flake in the cloud because the dev server was slow to start.
That was wrong: its `run_probe` double had a stale signature, the activity raised `TypeError`,
and — because `TemporalOps` set no retry policy and so inherited Temporal's *unlimited*
retries — it retried forever. The test hung on any machine, indefinitely. Both the double and
the retry policy are fixed; it now passes in seconds.

## 2. Live-model run against the test endpoint

The harness talks to any OpenAI-spec endpoint. For testing use **`llm.almckay.io`**, which
needs **no API key**. Select the OpenAI-spec ("gateway") backend and turn on live mode:

```bash
export HARNESS_MODEL_MODE=live
export HARNESS_MODEL_BACKEND=gateway     # config/models.yaml -> backends.gateway
# base_url is already set to https://llm.almckay.io/v1 in config/models.yaml.
# No HARNESS_OPENAI_API_KEY needed for this endpoint.
```

Then score the seeded corpus end to end (with the gVisor sandbox on, or `--no-sandbox` to
skip building/probing and exercise only the model-driven agents):

```bash
uv run harness eval corpus                 # real verdicts + tool/skill evocation
uv run harness eval corpus --no-sandbox    # agents only, no Docker needed
# or a single agent's dataset:
uv run harness eval run verdict
uv run harness eval run probe-diagnosis
```

Results from this run, and the problems it exposed, are written up in
[`LIVE_VALIDATION.md`](LIVE_VALIDATION.md).

Under a live model these produce real numbers where stub mode shows placeholders:
per-class accuracy, the false-negative rate on truly-exploitable cases, and — from the
trajectory evaluators — the rate at which `context` / `probe-author` / `recon` /
`env-planner` actually call the expected tools and load the matching skill.

> If a model tier resolves to a name the endpoint doesn't serve, edit `model_catalog` in
> `config/models.yaml` (the `gateway:` column) to the model ids `llm.almckay.io` exposes,
> then re-run. A quick way to see what a run sent/received is the OTel trace UI (below) or
> the per-agent trace in the web finding-detail view.

### Bedrock instead (optional)

```bash
aws sso login --profile infosec-harness-sso
export HARNESS_MODEL_MODE=live HARNESS_MODEL_BACKEND=bedrock
```

Confirm the Bedrock model ids/region in `config/models.yaml` match what your account has
enabled (add a `us.`/`global.` inference-profile prefix if required).

## 3. Full stack

```bash
docker compose up --build
```

Brings up Postgres, Temporal (+ UI at :8233), MinIO (:9001), an OpenTelemetry collector +
Jaeger (:16686), the worker, the API (:8000, docs at `/docs`), and the web app (:8080).
Set the same `HARNESS_MODEL_MODE`/`HARNESS_MODEL_BACKEND` env before `up` for a live stack;
default is stub, so it also runs with nothing configured.

## 4. Database migrations

The API container runs `harness migrate` before it serves, so a `docker compose up` after a
schema change is enough. Outside compose:

```bash
uv run harness migrate            # against HARNESS_DATABASE_URL; adopts a pre-alembic database
just migrate                      # the same, against the local .harness/demo.db
uv run alembic current            # which revision a database is at
uv run alembic upgrade head --sql # print the SQL instead of running it (for a DBA-applied change)
```

A database created by `harness init-db` (or `just demo`) before this existed has tables but no
`alembic_version` row. `harness migrate` recognises that shape, stamps it at revision `0001` —
which is exactly what the old `init-db` built — and upgrades from there. A brand-new database
is stamped at head by `init-db` itself, so either entry point leaves it in a state the other
understands. If a local `.harness/demo.db` fails with *no such column*, run `just migrate`.

## Sandbox (gVisor) {#sandbox-gvisor}

Real builds and probes run under gVisor. Install `runsc` and register it as a Docker
runtime (see the gVisor docs), then confirm:

```bash
docker info --format '{{json .Runtimes}}'   # must list "runsc"
```

- Builds and probes **fail closed** if `runsc` is missing. For local development without
  gVisor, set `HARNESS_ALLOW_INSECURE_RUNTIME=true` (weaker isolation — dev only).
- The build step uses a buildx builder (`harness-gvisor`, created automatically by the
  worker) so untrusted install scripts are gVisor-contained; build egress is pinned to the
  registry allowlist via the `egress-proxy` service in compose.
- Kubernetes manifests for the isolated probe namespace are under `deploy/k8s/`.

**gVisor has now run, on a Mac, via a Linux VM.** `runsc` inside a dedicated podman
machine with a `docker`->podman shim; the harness's fail-closed check passes on the real
runtime with no `HARNESS_ALLOW_INSECURE_RUNTIME`. The Python corpus scores 90% with a 25%
false-negative rate on exploitable cases — see
[`LIVE_VALIDATION.md`](LIVE_VALIDATION.md) for the setup and the four defects it found.
Still outstanding: **build-time** containment (buildah does not persist layers under
runsc, so builds run under crun), and the production `docker` + `runsc` path.
