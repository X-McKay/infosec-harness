# InfoSec Harness

## New developer quickstart

On Apple Silicon macOS or Debian/Ubuntu x86-64 Linux, clone the repository and run:

```bash
./dev
```

The launcher manages pinned tools and a checkout-owned Lima VM with Docker and runsc,
without changing host Docker configuration. It installs locked dependencies, allocates
loopback ports, checks sandbox and build-egress fixtures, and runs a stub demonstration
through the API and Temporal worker. Linux may require sudo for QEMU installation. The default uses
stub inference and makes no provider request. It reports the web, API, Temporal UI, and log
locations when ready. The full profile mounts this checkout into the API, worker, and Vite web
services; run `./dev reload` after backend edits, while web edits reload through Vite. `./dev stop` stops only this checkout's project and preserves its volumes.

For component work on a host without the required isolated runtime, use:

```bash
./dev --profile offline
```

Offline mode runs the locked stub/component checks and explicitly leaves the API, Temporal, web,
and real sandbox gates as `not_checked`; it is not a full-stack acceptance result. See
[`docs/LOCAL_SETUP.md`](docs/LOCAL_SETUP.md) for host requirements, recovery, and troubleshooting.

A durable graph of [PydanticAI](https://pydantic.dev/docs/ai/) agents that **filters,
prioritizes, and triages pre-identified vulnerability findings** for exploitability. For
each finding it profiles the target repository, works out how to build and test it, drafts
a targeted unit-test probe, runs the probe in an isolated sandbox, and returns one of
`potentially_exploitable` / `likely_not_exploitable` / `inconclusive` with evidence and a
priority.

It does not scan for new vulnerabilities, write fixes, or touch production. Probes run only
against code in a sandbox. See [`docs/redesign/SPEC.md`](docs/redesign/SPEC.md) for the full
design and decision log.

## How it works

- **Agents are data.** Each of the 11 agents is one pydantic-ai Agent Spec
  (`agents/<name>/agent.yaml`): a prompt, a model tier, cache settings, and a skills list.
  Typed I/O, the capability allowlist, and the verdict contract stay in code. Skills
  (`skills/*/SKILL.md`) give per-CWE, per-language, per-framework guidance on demand.
- **Two Temporal workflows.** `RepoPreparationWorkflow` runs once per repo@revision
  (recon → environment plan → build with an aggressive repair loop and a partial-build
  fallback → smoke test) and is cached. `FindingTriageWorkflow` runs the per-finding graph
  (context → probe plan → author → execute → diagnose → repair loop → verdict). The
  pydantic-graph topology runs *inside* the workflow; agents are `TemporalDurability` agents
  whose model and tool calls become activities.
- **Deterministic where it counts.** Stack detection, building, probe execution, the
  three-way verdict contract, prioritization, and cost accounting are plain code. Probes
  decide exploitability from an explicit oracle signal, never from a passing test.
- **Sandbox.** Build and probe containers run under gVisor (`runsc`), non-root,
  read-only-root, resource-capped, and with **no network at probe time**.
- **Models.** Switchable per deployment and per agent: AWS Bedrock (SSO profile locally,
  IRSA in k8s) or configured OpenAI-compatible chat-completions endpoints. A `stub` mode runs the whole
  pipeline deterministically with no credentials.
- **Prompt caching.** A stable→volatile prompt layout, pinned model/thinking per agent, and
  repo-grouped warm-then-fan-out scheduling keep the shared prefix served from cache; cache
  tokens are recorded per call. Both halves are checked offline by `tests/test_cache_prefix.py`,
  which also records the one thing that breaks the prefix: history compaction rewrites it, so a
  run long enough to need compaction pays full prefill afterwards. That is why the read tools
  answer in few, large calls (`tests/test_exploration_cost.py`) — a short run needs neither.
- **Evidence-based tuning.** Every agent has an eval dataset and an executable release
  policy. `harness eval run <agent> -m sonnet -m opus` runs the same dataset against each model
  in turn and prints accuracy, latency and cost side by side; every run is stored with the
  model, the commit, and whether that commit's tree was clean, and the accepted result per
  agent per model is committed under [`evals/baselines/`](evals/baselines/README.md).
- **Governed.** Each agent declares an owner, execution class, governance tier, data
  classification, model policy, and an enforced per-run budget; each toolset declares its
  effect on external state; each agent has a risk assessment whose tier its spec must match.
  Construction fails if any of that is missing. `just conformance` checks the whole thing
  against the Agent and Multi-Agent Playbooks — see
  [`docs/PLAYBOOK_CONFORMANCE.md`](docs/PLAYBOOK_CONFORMANCE.md).

## Quick start (offline, no credentials)

```bash
just bootstrap          # uv sync
just check              # ruff + compile + validate all agent specs
just test               # full suite, stub models, SQLite (Temporal test needs the `temporal` CLI)
just demo               # run the full pipeline in-process on examples/findings.sample.json
```

`just demo` prints a verdict and priority per finding. In `stub` mode verdicts are
deliberately `inconclusive` (the stub is not a real judge) — it exercises the plumbing, not
accuracy. Historical live-model observations — per-class accuracy, tool/skill evocation, and
endpoint-compatibility problems stubs cannot show — are recorded in
[`docs/LIVE_VALIDATION.md`](docs/LIVE_VALIDATION.md).

## Managed full stack

```bash
./dev
```

The managed launcher provisions the checkout-owned VM and starts Postgres, Temporal (+ UI at
:8233), the RustFS S3-compatible service (the `minio` compose DNS name, console at :9001), an
OpenTelemetry collector with Jaeger (:16686), the worker, the API (:8000, docs at `/docs`), and
the Vite web app. It generates per-checkout PostgreSQL and S3 credentials in `.harness/dev.env`.

- **Stub models** are the default, so the stack runs with no credentials.
- **Bedrock:** `aws sso login --profile infosec-harness-sso` on the host, then
  `HARNESS_MODEL_MODE=live docker compose up` (mounts `~/.aws`).
- **OpenAI-spec:** `HARNESS_MODEL_MODE=live HARNESS_MODEL_BACKEND=gateway
  HARNESS_OPENAI_API_KEY=sk-… docker compose up` (edit the endpoint in `config/models.yaml`).
The managed compose overlay runs trusted infrastructure containers under Docker's `runc` and
keeps untrusted BuildKit build steps and probes under `runsc`. Secure build egress requires the
static numeric proxy address generated by `./dev` (`HARNESS_BUILD_EGRESS_HOST_IP` and its matching
`HARNESS_BUILD_EGRESS_PROXY`); do not replace it with a DNS hostname. The base compose file is an
advanced manual path and is not the verified managed setup.

### Database schema

The run store's schema is versioned with Alembic. The revisions ship inside the package
(`src/infosec_harness/persistence/migrations/`) so `harness migrate` works from an installed
wheel — the API container runs it on startup — and the URL always comes from
`HARNESS_DATABASE_URL`, so a migration and the harness that reads the result can never
disagree about which database they mean.

- `harness migrate` — upgrade to the latest revision. A database built by `init-db` before
  migrations existed is adopted automatically (stamped at the baseline, then upgraded).
- `harness init-db` — bootstrap a fresh database from the models and stamp it at head. This
  is what tests, CI and `just demo` use; it never alters an existing table.
- Changing a model in `persistence/db.py` means adding a revision:
  `uv run alembic revision --autogenerate -m "…"`, then review it — a `NOT NULL` column needs
  a server default so the `ALTER` succeeds on populated tables (see `0002` for the pattern).
  `tests/test_migrations.py` fails if the revisions and the models ever disagree.

## CLI

```bash
harness submit findings.json [--local]   # triage a batch (JSON: one finding, a list, or {findings:[...]})
harness runs [--verdict … --batch-id …]  # list runs, highest priority first
harness report <run-id>                  # full triage report as JSON
harness eval run <agent> [-m sonnet -m opus] [--repeat N]  # one dataset, one model per -m
harness eval corpus [--language all --repeat N --no-sandbox]  # score the ground-truth corpus
harness eval results [--agent … --commit …]   # every stored run, with its model and commit
harness eval compare --agent <name>      # latest run per model, side by side
harness eval compare <exp-a> <exp-b> […]  # named experiments, accuracy / cost / latency
harness eval baseline save <exp-id>      # record the accepted result under evals/baselines/
harness eval baseline list
harness worker | harness api
harness migrate                          # alembic upgrade head (adopts a pre-alembic DB); init-db bootstraps a fresh one
harness agents validate | agents schema
```

## Layout

The split is the one agent-playbook 02 draws: anything an agent needs *in order to run* is
package data and ships in the wheel; anything reviewers and CI read *about* the system stays at
the repository root and is absent from a deployment.

```
src/infosec_harness/
  agents/<name>/agent.yaml  # the 11 agent specs (+ evals/dataset.yaml, evals/release-policy.yaml)
  skills/                   # SKILL.md libraries: probe-oracle-protocol, cwe-*, lang-*, build-*, test-*
  config/models.yaml        # the approved-model catalogue — governance data, so it ships with the code
  tools/          # per-toolset tool.yaml: effect, retry safety, timeout, output bound
  resources.py    # where the above are, whether this runs from a checkout or a wheel
  domain/         # typed contracts (Finding, EnvironmentSpec, ProbePlan, Verdict, …)
  agents/*.py     # loader, model factory, custom capabilities, stubs, validators
  graph/          # pydantic-graph triage flow, prepare orchestrator, Ops interface, scoring
  workflows/      # Temporal workflows, activities, TemporalOps, worker, runner
  sandbox/        # gVisor-capable Docker runner
  telemetry.py    # OTel resource attributes and agent-run spans
  persistence/    # SQLAlchemy models, store, artifact store (MinIO/filesystem), alembic migrations/
  intake/ integrations/ado  # generic JSON + Azure DevOps intake and comment-only write-back
  evals/          # per-agent eval runner and compare
  api/ cli.py     # FastAPI service and Typer CLI

systems/triage-system/     # System Spec + delegation / data-flow / termination policies
docs/risk-assessments/     # one per agent + the system; generated from scripts/risk_scenarios.py
eval-corpus/               # paired vulnerable/fixed fixture repositories
scripts/                   # generators for the governance artifacts, and the conformance check
tests/
web/                       # React + shadcn triage UI (client generated from the API's OpenAPI)
deploy/                    # compose support (postgres init, otel collector)
```

A spec addresses its resources by their path *inside the distribution* — `directories: skills`,
`evaluation_policy: agents/<name>/evals/release-policy.yaml` — and
`infosec_harness.resources` resolves them through `importlib.resources`. Nothing reads them
relative to the process working directory; `tests/test_packaging.py` builds the real wheel,
installs it, and asserts all 11 agents construct from an unrelated directory.
