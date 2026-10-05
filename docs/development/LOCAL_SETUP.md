# Local setup

The supported entry point is `./dev`. It is safe to run repeatedly and scopes compose resources
to the absolute checkout path, so several worktrees can run side by side without sharing volumes
or fixed host ports. The default profile is strict: it requires an actual `runsc` execution probe
before starting the stack. A runtime name in Docker's inventory is not isolation evidence.

## Host requirements

The managed reference targets are Apple Silicon macOS (VZ) and Debian/Ubuntu x86-64 Linux
(QEMU/KVM; missing QEMU packages may prompt for sudo). Hardware virtualization, network access
for the first downloads and roughly 8 GiB of free VM memory are required. Host Docker is not
needed, and host Docker contexts, daemon settings, shell profiles and global tools are never
changed. Other Linux distributions need their QEMU prerequisite installed separately.

Tool versions and download hashes (Python, uv, Node, just and the Temporal CLI) live in
`.mise.toml`; `.dev-tools/versions.env` pins only mise and Lima, which are needed before mise
exists; the VM image is pinned in `deploy/dev-runtime/lima.yaml`. Managed tools, downloads and
generated configuration live under the ignored `.harness/` directory. VM state uses a short
per-checkout directory under `~/.cache/ih/` because macOS limits UNIX socket path lengths;
`.harness/runtime-home` records its exact location.

## Commands

```bash
./dev [--profile full|offline] [COMMAND]
./dev                   # start: tools, VM, sandbox fixtures, stack, stub assessment
./dev check | test      # just check / just test with the pinned tools
./dev status            # compose service status (offline: pinned tools present)
./dev logs [SERVICE]    # bounded log snapshot, also saved under .harness/logs/
./dev smoke             # re-run readiness, sandbox fixtures and the stub assessment
./dev doctor            # pinned tools, VM and sandbox fixtures, without starting services
./dev validate          # read-only checks against the running stack (below)
./dev reload            # restart the editable API and worker, then the stub/runtime smoke
./dev reload-ui         # restart API and web, then GET-only integration checks
./dev stop [--vm]       # stop the stack; --vm also stops the VM
./dev reset [--yes]     # delete this checkout's VM, volumes, findings and generated config
./dev gc [--delete]     # list (or delete) VM homes whose checkout no longer exists
```

`./dev stop` preserves the VM, volumes, findings, downloads and generated configuration.
`./dev reset` is the only command that deletes them; it asks for confirmation unless `--yes`
is given and keeps pinned tools and reports.

`.harness/dev.env` records the checkout's compose identity, loopback ports and generated
PostgreSQL and S3 credentials (mode 0600, ignored by Git). Existing values are preserved across
runs. If startup is interrupted, rerun `./dev` and inspect `./dev status` and
`./dev logs <service>`. Managed container logs rotate at 10 MiB with three files per service.

The full profile mounts the checkout read-only into the API and worker (installed editable) and
runs Vite against `ui/`. Backend edits take effect after `./dev reload`; frontend edits hot
reload. The stack runs PostgreSQL 16, Temporal and its UI, RustFS as the S3-compatible artifact store
(the compose service is still named `minio`), an OpenTelemetry collector with Jaeger, the
worker, the API (OpenAPI docs at `/docs`) and the web app. Temporal history and visibility use
separate PostgreSQL databases. Every image is pinned by digest. The dev profile sets
`HARNESS_LOCAL_REPO_ROOTS` to the eval corpus and the launcher's smoke fixture, so assessments
can use those local repositories; any other local `repo_url` is refused.

`./dev reload-ui` checks the typed runtime and qualification endpoints through both the API and
the web proxy, the operational collections (empty is valid) and the served assets. It submits
nothing, writes nothing and makes no model request, and it waits up to 60 seconds for transient
startup failures. Restarting the API runs its normal startup, so accepted submissions may resume.
For explicit release identity checks run `scripts/ui_deployment_smoke.py` with
`--expected-source-commit`, `--expected-model-mode` and `--expected-transport`.

### Offline profile

```bash
./dev --profile offline
```

Installs the pinned tools and locked dependencies, then runs `just check` and `just test` with
stub models. The API, Temporal service, web, persistence integration and sandbox boundary are
`not_checked`; keep that distinction in any evidence. Do not set
`HARNESS_ALLOW_INSECURE_RUNTIME=true` to turn a failed full profile into a passing isolation
result: the override exists for explicitly labelled local development only.

### Read-only service validation

`./dev validate` checks the configured database and migration head, recent workflow and activity
pollers for the running worker, API and worker source and model-profile consistency, API
contracts, the UI assets and the same-origin proxy. It does not start services, migrate,
submit findings or recover broker requests. The same checks are available to operators as
`harness readiness` (database, schema head and Temporal pollers; `--worker-hostname`,
`--timeout`) and `harness model-connectivity --model` (one structured-output request).

```bash
./dev validate --model                       # add one explicit inference request
./dev validate --model --connectivity-receipt .harness/local-model/connectivity.json
./dev validate --expected-source-commit "$(git rev-parse HEAD)"
```

The model check makes one request with no retry against the configured live verdict backend.
Stub, brokered and unsupported profiles stay `not_checked` without a request. A successful call
is connectivity, not an agent evaluation. Reports are private, atomically written JSON under
`.harness/reports/service-validation/` (`--report` selects another path); exit codes are 0
(`passed`), 1 (`failed`) and 2 (`not_checked`). The optional receipt is written only after a
successful exact-profile request; the API reads it from `HARNESS_MODEL_CONNECTION_OBSERVATION`
(see [qualification dashboard](../operations/QUALIFICATION_DASHBOARD.md)). `--timeout` bounds
each service operation (default 30 s, 1-60) and `--model-timeout` the request (default 90 s,
1-300). `./dev --profile offline validate` contacts nothing and reports every gate `not_checked`.

## Live models

Stub inference is the default everywhere. To use a real model, configure a model gateway
endpoint or Bedrock explicitly; nothing in the packaged catalogue points at a usable endpoint.

```bash
export HARNESS_MODEL_MODE=live
export HARNESS_MODEL_BACKEND=gateway                 # an OpenAI-compatible endpoint
export HARNESS_MODEL_BASE_URL=https://gateway.example.internal/v1
export HARNESS_OPENAI_API_KEY=...                    # if the gateway requires one
```

[Model endpoints](../operations/MODEL_ENDPOINTS.md) covers mapping model tiers to the ids the
endpoint serves, checking it, and reasoning-budget options. For Bedrock, run
`aws sso login --profile infosec-harness-sso` and set `HARNESS_MODEL_BACKEND=bedrock`; confirm
the model ids and region in `src/infosec_harness/config/models.yaml` match your account.

Real assessments always run through Temporal. `harness submit --local` and the API's
`mode: local` run stub models only. Agent evals (`harness eval run`) and the corpus runner
(`harness eval corpus`, with `--no-sandbox` to skip building and probing) may call a live model
directly.

## Without the launcher

`./dev` manages the reference environment; these are manual paths for component work.

```bash
just bootstrap      # uv sync --locked
just check          # ruff over src, tests and scripts; compile; validate every agent spec
just test           # deterministic suite, stub models, per-process SQLite
just demo           # the pipeline in-process on examples/findings.sample.json
```

`just` and `uv` here must be the pinned versions: run them through
`.harness/bin/mise exec -- just <recipe>` once `./dev` has installed the tools. Tests marked
`requires_temporal` (for example `tests/runtime/test_workflow_integration.py`) start the pinned
Temporal CLI dev server and skip without it; `HARNESS_TEST_REQUIRE_TEMPORAL=1` makes that a
failure. The suite refuses an ambient `HARNESS_MODEL_MODE` other than `stub` or an ambient
database URL unless `HARNESS_TEST_ALLOW_LIVE=1` or `HARNESS_TEST_DATABASE_URL` is set.

The base `docker-compose.yml` is an advanced manual path. It does not reuse the managed VM,
generated credentials or allocated ports, and it is not the verified setup.

## Database migrations

The run store is versioned with Alembic; the revisions ship in
`src/infosec_harness/persistence/migrations/`. Schema bootstrap (API startup, `harness init-db`,
`harness submit` and eval runs) creates an empty database at head, accepts one already at head,
and refuses anything else with the command that fixes it. The API container runs
`harness migrate` before it serves.

```bash
uv run harness migrate            # upgrade HARNESS_DATABASE_URL to head
just migrate                      # the same, against the demo database .harness/demo.db
uv run alembic current            # which revision a database is at
uv run alembic upgrade head --sql # print the SQL for a DBA-applied change
```

`harness init-db` creates an empty database at head and is what tests, CI and `just demo` use;
it never alters an existing table. A database with tables but no Alembic version row is refused
rather than guessed at. Changing a model in `src/infosec_harness/persistence/db.py` means adding
a revision (`uv run alembic revision --autogenerate -m "..."`) and reviewing it: a `NOT NULL`
column needs a server default. `tests/persistence/test_migrations.py` fails if the revisions and
the models disagree.

## Sandbox

Untrusted build steps and probes run under gVisor; trusted infrastructure containers use
Docker's `runc`. `ensure_runtime_available` refuses any configured runtime other than `runsc`,
and `Settings` refuses one at startup, unless `HARNESS_ALLOW_INSECURE_RUNTIME=true`. Builds use
a buildx builder (`harness-gvisor`, created by the worker) on an internal network whose only
egress is the operator's allowlisting proxy (`deploy/squid-allowlist.conf`); the generated
`HARNESS_BUILD_EGRESS_HOST_IP` and matching `HARNESS_BUILD_EGRESS_PROXY` must stay numeric,
because runsc cannot use Docker's embedded DNS on an internal bridge. Probes and the sandbox
shell tool have no network. Kubernetes manifests for an isolated probe namespace are under
`deploy/k8s/`.

For a manual setup, install `runsc`, register it as a Docker runtime, and check with
`docker info --format '{{json .Runtimes}}'`; that is discovery only, and an actual execution must
also pass.

## Package dependency compatibility

Use the lockfile for checkout development (`uv sync --locked`). Installed wheels support
`temporalio>=1.33,<1.34`: Temporal 1.34 added an `ActivityConfig` field that the current
PydanticAI integration cannot turn into a Pydantic schema. Revisit the bound with isolated wheel
construction and real Temporal replay checks before admitting another version.
