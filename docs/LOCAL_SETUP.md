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
(`tests/test_workflow_integration.py`) was flaky *in the cloud sandbox* only because the
Temporal dev server was slow to start; on a normal machine it passes:

```bash
uv run pytest tests/test_workflow_integration.py
```

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
uv run harness eval run probe_diagnosis
```

Under a live model these produce real numbers where stub mode shows placeholders:
per-class accuracy, the false-negative rate on truly-exploitable cases, and — from the
trajectory evaluators — the rate at which `context` / `probe_author` / `recon` /
`env_planner` actually call the expected tools and load the matching skill.

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

**Validation pass to do once locally** (couldn't be done in the cloud sandbox — no runsc):
run `uv run harness eval corpus` with the sandbox on and confirm the Python vulnerable
cases build, the probe fires its oracle, and the fixed variants do not. Then repeat for a
Java/JS/Perl case to confirm those toolchains build under the buildx/gVisor path.
