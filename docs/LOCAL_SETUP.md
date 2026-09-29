# Local setup

The supported entry point is `./dev`. It is safe to run repeatedly and keeps compose resources
scoped to the absolute checkout path, which allows multiple worktrees to run without sharing
volumes or fixed host ports. The default profile is intentionally strict: it requires an actual
`runsc` execution probe before starting the stack. A runtime name in Docker's inventory alone is
not accepted as isolation evidence.

## Quickstart

The managed reference targets are Apple Silicon macOS and Debian/Ubuntu x86-64 Linux.
The launcher downloads checksum-verified mise and Lima, installs pinned Python/uv/Node/just,
and provisions a checkout-owned Linux VM with Docker and runsc. macOS uses VZ; Linux uses
QEMU/KVM and may request sudo to install missing QEMU packages. Hardware virtualization,
network access for initial downloads, and roughly 8 GiB of available VM memory are required.
Host Docker is unnecessary, and host Docker contexts, daemon settings and shell profiles are
not changed. Other Linux distributions need their QEMU prerequisite installed separately.

Versions and download hashes live in [`.dev-tools/versions.env`](../.dev-tools/versions.env),
`.mise.toml`, and `deploy/dev-runtime/lima.yaml`. Managed tools, downloads and configuration live
beneath the ignored `.harness/` directory. VM state uses a short per-checkout directory under
`~/.cache/ih/` because macOS limits UNIX socket path lengths. `.harness/runtime-home` records
its exact location. Platform support remains subject to the acceptance limits below.
```bash
./dev
./dev status
./dev logs api
./dev reload  # restart API and worker after backend edits
./dev stop
```

The generated `.harness/dev.env` records the per-checkout compose identity and loopback ports.
Existing project identity, ports, and local service credentials are preserved. This file
contains generated PostgreSQL/RustFS S3 credentials, is mode 0600, and is ignored by Git. The first run
may download dependencies and images; a warm run reuses them. If startup is interrupted, rerun
`./dev`; inspect `./dev status` and `./dev logs <service>` for bounded failure details. `stop`
preserves local findings and volumes. No destructive reset is part of the launcher.

The full compose profile uses `docker-compose.dev.yml`: API and worker source are mounted
read-only and installed editable inside the image, while the web container runs Vite against the
mounted `web/` tree. Backend edits take effect after `./dev reload` restarts the API/worker processes; frontend edits use
Vite's normal hot reload. The packaged nginx image remains available through the base compose
file for deployment-oriented checks.

`./dev smoke` repeats the API readiness and actual sandbox fixture checks. It does not infer model
quality from stub inference. `./dev doctor` reports host/runtime readiness without starting
services. Provider credentials are optional and are never required by the default profile.

### Offline component profile

When virtualization or the required runtime is unavailable:

```bash
./dev --profile offline
```

This installs the locked Python dependencies and runs agent validation with stub inference. It
does not check the real API, Temporal, web, persistence integration, or sandbox boundary. Keep
that distinction in evidence reports. Do not set `HARNESS_ALLOW_INSECURE_RUNTIME=true` to turn a
failed full profile into a green isolation result; that override is for explicitly labeled local
development only.

### Current onboarding evidence limits

Clean-host macOS/Linux acceptance, real build/probe isolation, and warm restart are tracked
in [IMPLEMENTATION_VALIDATION.md](IMPLEMENTATION_VALIDATION.md). A managed VM configuration
is not proof that these gates passed. The offline profile and browser fixture review do not
substitute for real execution evidence.

### Generated development skills

Author development skills under `dev-skills/`. `just generated-sync` copies them to both
`.agents/skills/` (Codex discovery) and `.claude/skills/` (Claude discovery); `just generated-check`
and CI verify drift without rewriting files. The packaged runtime skills under
`src/infosec_harness/skills/` are a separate source of truth.

How to run the harness on your own machine, including a live-model run against the test
endpoint. Day-to-day work lands on `develop`; `main` is what has been released.

## Manual setup prerequisites

The following sections are optional manual/operator paths; `./dev` manages the reference
development environment. Real operational submissions require Temporal. `harness submit
--local` is restricted to stub demonstrations; controlled component evals may run locally.

- Python 3.12 and [`uv`](https://docs.astral.sh/uv/)
- `just` (task runner) — optional but assumed below
- Docker (for the full stack and for real sandboxed builds/probes)
- Node 22 + npm (only for the web app)
- gVisor (`runsc`) for real probe isolation — see [Sandbox](#sandbox-gvisor). The managed
  launcher provisions and verifies it; without it, builds/probes fail closed.

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

## 2. Historical live-model validation

The following endpoint instructions and report are historical validation material, not a current
onboarding or acceptance path. They do not establish that a live model has been tested on the
managed launcher.

The harness supports configured OpenAI-compatible chat-completions profiles. For testing use **`llm.almckay.io`**, which
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

The historical report records model-dependent measurements that stub mode cannot provide,
including per-class accuracy and trajectory tool/skill evocation. Treat those measurements as
historical and descriptive; they are not current managed-runtime acceptance evidence.

> If a model tier resolves to a name the endpoint doesn't serve, edit `model_catalog` in
> `config/models.yaml` (the `gateway:` column) to the model ids `llm.almckay.io` exposes,
> then re-run. The OTel trace UI and finding detail expose operational metadata; prompts and
> completions are excluded from trace exports.

### Bedrock instead (optional)

```bash
aws sso login --profile infosec-harness-sso
export HARNESS_MODEL_MODE=live HARNESS_MODEL_BACKEND=bedrock
```

Confirm the Bedrock model ids/region in `config/models.yaml` match what your account has
enabled (add a `us.`/`global.` inference-profile prefix if required).

## 3. Full stack

```bash
./dev
```

The managed profile brings up Postgres, Temporal (+ UI at :8233), RustFS (an S3-compatible
service addressed as `minio` inside compose, console at :9001), an OpenTelemetry collector +
Jaeger (:16686), the worker, the API (:8000, docs at `/docs`), and the web app (:8080). It
generates PostgreSQL and S3 credentials in `.harness/dev.env`; default inference is stub.
Use `./dev status`, `./dev logs <service>`, `./dev smoke`, and `./dev stop` for lifecycle
operations. The base `docker-compose.yml` remains an advanced manual path and is not equivalent
to the verified managed setup.

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

Untrusted BuildKit build steps and probes run under gVisor. Trusted infrastructure containers
use Docker's `runc`. The managed launcher provisions `runsc` and verifies an actual execution
probe before starting the full profile. Its build egress network uses a static numeric proxy
address because the runsc network stack cannot use Docker's embedded DNS on the internal bridge.
The generated `HARNESS_BUILD_EGRESS_HOST_IP` and matching `HARNESS_BUILD_EGRESS_PROXY` must stay
numeric and aligned.

For an advanced manual setup, install `runsc` and register it as a Docker runtime (see the
gVisor docs), then confirm:

```bash
docker info --format '{{json .Runtimes}}'   # must list "runsc"
```

- Builds and probes **fail closed** if `runsc` is missing.
- The build step uses a buildx builder (`harness-gvisor`, created automatically by the
  worker) so untrusted install scripts are gVisor-contained; build egress is pinned to the
  registry allowlist via the `egress-proxy` service in compose.
- Kubernetes manifests for the isolated probe namespace are under `deploy/k8s/`.

The historical live-model and podman-based runtime notes remain in
[`LIVE_VALIDATION.md`](LIVE_VALIDATION.md) as historical evidence only. They do not describe
the managed launcher or establish clean-host acceptance.
