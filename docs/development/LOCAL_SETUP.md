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

Versions and download hashes live in [`.dev-tools/versions.env`](../../.dev-tools/versions.env),
`.mise.toml`, and `deploy/dev-runtime/lima.yaml`. Managed tools, downloads and configuration live
beneath the ignored `.harness/` directory. VM state uses a short per-checkout directory under
`~/.cache/ih/` because macOS limits UNIX socket path lengths. `.harness/runtime-home` records
its exact location. Platform support remains subject to the acceptance limits below.
```bash
./dev
./dev status
./dev logs api
./dev reload  # restart API/worker and run the explicit stub/runtime smoke
./dev reload-ui  # restart API/web; GET-only checks without seeded findings
./dev stop
```

The generated `.harness/dev.env` records the per-checkout compose identity and loopback ports.
Existing project identity, ports, and local service credentials are preserved. This file
contains generated PostgreSQL/RustFS S3 credentials, is mode 0600, and is ignored by Git. The first run
may download dependencies and images; a warm run reuses them. If startup is interrupted, rerun
`./dev`; inspect `./dev status` and `./dev logs <service>` for bounded failure details. Log snapshots are saved under `.harness/logs/`;
managed container logs rotate at 10 MiB with three files per service. `stop`
preserves local findings and volumes. No destructive reset is part of the launcher.

The full compose profile uses `docker-compose.dev.yml`: API and worker source are mounted
read-only and installed editable inside the image, while the web container runs Vite against the
mounted `ui/` tree. Backend edits take effect after `./dev reload` restarts the API/worker processes; frontend edits use
Vite's normal hot reload. The packaged nginx image remains available through the base compose
file for deployment-oriented checks.

`./dev smoke` repeats API/web/storage readiness, actual sandbox fixtures, and the completed
demo query against Temporal visibility. History and visibility use separate PostgreSQL
databases (`temporal` and `temporal_visibility`), so their independent schema version tables
cannot suppress visibility migrations. Existing volumes are preserved; Temporal auto-setup
creates the missing visibility database on an upgraded local stack. It does not infer model
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
in [IMPLEMENTATION_VALIDATION.md](../validation/IMPLEMENTATION_VALIDATION.md). A managed VM configuration
is not proof that these gates passed. The offline profile and browser fixture review do not
substitute for real execution evidence.

### Generated development skills

Author development skills under `dev-skills/`. `just generated-sync` copies them to both
`.agents/skills/` (Codex discovery) and `.claude/skills/` (Claude discovery); `just generated-check`
and CI verify drift without rewriting files. The packaged runtime skills under
`src/infosec_harness/skills/` are a separate source of truth.

For code navigation and output ownership, see [REPOSITORY_GUIDE.md](REPOSITORY_GUIDE.md).

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
(`tests/runtime/test_workflow_integration.py`) needs the `temporal` CLI on PATH and skips without it:

```bash
uv run pytest tests/runtime/test_workflow_integration.py
```

## 2. Historical live-model validation

The following endpoint instructions and report are historical validation material, not a current
onboarding or acceptance path. They do not establish that a live model has been tested on the
managed launcher.

The harness supports configured OpenAI-compatible chat-completions profiles. For testing use **`llm.almckay.io`**, which
needs **no API key**. Select the OpenAI-spec ("gateway") backend and turn on live mode:

```bash
export HARNESS_MODEL_MODE=live
export HARNESS_MODEL_BACKEND=gateway     # src/infosec_harness/config/models.yaml -> backends.gateway
# base_url is already set to https://llm.almckay.io/v1 in src/infosec_harness/config/models.yaml.
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
[`LIVE_VALIDATION.md`](../validation/LIVE_VALIDATION.md).

The historical report records model-dependent measurements that stub mode cannot provide,
including per-class accuracy and trajectory tool/skill evocation. Treat those measurements as
historical and descriptive; they are not current managed-runtime acceptance evidence.

> If a model tier resolves to a name the endpoint doesn't serve, edit `model_catalog` in
> `src/infosec_harness/config/models.yaml` (the `gateway:` column) to the model ids `llm.almckay.io` exposes,
> then re-run. The OTel trace UI and finding detail expose operational metadata; prompts and
> completions are excluded from trace exports.

### Bedrock instead (optional)

```bash
aws sso login --profile infosec-harness-sso
export HARNESS_MODEL_MODE=live HARNESS_MODEL_BACKEND=bedrock
```

Confirm the Bedrock model ids/region in `src/infosec_harness/config/models.yaml` match what your account has
enabled (add a `us.`/`global.` inference-profile prefix if required).

## 3. Full stack

```bash
./dev
```

The managed profile brings up Postgres, Temporal and its UI, RustFS (an S3-compatible service addressed as `minio` inside
compose), an OpenTelemetry collector, Jaeger, the worker, the API (docs at `/docs`), and the web
app. Read the allocated loopback URLs from launcher output or `.harness/dev.env`. It
generates PostgreSQL and S3 credentials in `.harness/dev.env`; default inference is stub.
Use `./dev status`, `./dev logs <service>`, `./dev smoke`, and `./dev stop` for lifecycle
operations. The base `docker-compose.yml` remains an advanced manual path and is not equivalent
to the verified managed setup.

## Package dependency compatibility

Use the checked-in lockfile for checkout development (`uv sync --locked`). Installed wheels
support `temporalio>=1.33,<1.34`: Temporal 1.34 added an `EventGroup` field to `ActivityConfig`
that the current PydanticAI integration cannot turn into a Pydantic schema. Fresh wheel tests
reproduced the failure with PydanticAI 2.52 / Temporal 1.34 and constructed all 11 agents after
changing only Temporal to 1.33. The lockfile keeps its existing dependency versions; only the
supported-range metadata changed. Revisit this bound with isolated wheel construction and real
Temporal replay checks before admitting another version.

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
docker info --format '{{json .Runtimes}}'   # discovery only; actual execution must also pass
```

- Builds and probes **fail closed** if `runsc` is missing.
- The build step uses a buildx builder (`harness-gvisor`, created automatically by the
  worker) so untrusted install scripts are gVisor-contained; build egress is pinned to the
  registry allowlist via the `egress-proxy` service in compose.
- Kubernetes manifests for the isolated probe namespace are under `deploy/k8s/`.

The historical live-model and podman-based runtime notes remain in
[`LIVE_VALIDATION.md`](../validation/LIVE_VALIDATION.md) as historical evidence only. They do not describe
the managed launcher or establish clean-host acceptance.

For UI/API-only updates, `./dev reload-ui` verifies the typed runtime and qualification endpoints through both the API and the web proxy, operational collections (empty is valid), and actual served assets. It performs no finding submission, storage mutation or model request. A healthy old API cannot pass merely because `/api/health` returns 200. This command preserves the configured model profile; it does not silently switch a stub development environment to live inference. Configure live model access and operator evidence explicitly for an operational deployment.
