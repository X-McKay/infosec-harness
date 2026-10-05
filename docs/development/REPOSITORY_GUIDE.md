# Repository guide

## Where to change things

Paths below are relative to `src/infosec_harness/` unless they start at the repository root.

| Module | Responsibility |
| --- | --- |
| `domain/models.py`, `domain/canonical.py` | Typed findings, plans, verdicts and shared contracts; canonical JSON bytes and SHA-256 digests |
| `agents/` | Agent specs, eval datasets and release policies (`agents/<name>/`), the risk scenario library, the registry (agent bindings and `EXECUTION_GENERATION`), model factory, capabilities (which enforce the tool policies), prompt renderer (`render.py`), repository read tools (`repo_tools.py`), `trajectory.py` (tools called and skills loaded per run), budgets, stubs and validators |
| `graph/triage.py`, `graph/prepare.py`, `graph/local.py` | The per-finding triage graph, component preparation, and in-process discovery and preparation |
| `graph/pipeline.py`, `graph/workloads.py`, `graph/failures.py` | Grouping, scheduling and per-finding orchestration, the build/smoke/probe workloads, and failure classification, shared by the in-process and durable paths |
| `graph/ops.py`, `graph/manifests.py`, `graph/scoring.py` | The execution interface, secret-free reproduction manifests, prioritization |
| `workflows/workflows.py`, `workflows/activities.py`, `workflows/persistence_activities.py`, `workflows/worker.py` | Temporal workflows (`TriageBatch`, `ComponentPreparation`, `FindingTriage`), activities, the activities that write the durable record, and the worker |
| `workflows/payloads.py`, `workflows/activity_options.py` | Typed workflow and activity arguments; activity timeouts and retry policies |
| `workflows/submission.py`, `workflows/local_run.py`, `workflows/writeback.py` | Durable submission and cancellation; in-process stub runs; Azure DevOps comment write-back |
| `workflows/accounting.py` | Root budget reservations |
| `sandbox/docker.py` | The runtime gate and probe/shell/build execution; re-exports the sandbox's public names |
| `sandbox/{errors,markers,output,image,engine,boundary}.py` | Failure classes; stdout markers; parsing untrusted runner output; Dockerfile and image identity; the Docker CLI; egress network and builder verification |
| `sandbox/controls.py`, `sandbox/evidence.py`, `sandbox/policy.py`, `sandbox/process.py` | Positive and negative control tests; the controller's execution record; base-image allowlist and build-spec validation; the one owned subprocess runner for Docker, Git and native CLIs |
| `repo/` | Hardened Git checkout under `local_repo_roots`, access checks, component and stack detection |
| `persistence/` | Run store (`store.py`, `db.py`), migrations, artifacts, budgets, recipe cache, reconciliation; `run_telemetry.py` (the one typed `RunTelemetry`, schema 2; migration `0006` rewrote earlier records), `batch_progress.py` (read-only batch progress), `identity.py` (worker-host provenance and manifest `schema_version`), `paths.py` (workspace layout), `population.py` (operational/demo populations) |
| `inference/` | Opt-in credential broker, one subpackage per role (below) |
| `evals/` | `run.py` (eval runs, overlays and `--model`), `adapters.py` (per-agent scoring adapters), `dataset.py` (the one dataset loader), `gates.py` (the one release-gate evaluator), `release_report.py`, `inert_gates.py` (the audit every report gets), `metrics.py`, `messages.py` (captured-message walker), `pricing.py`, `baselines.py`, `corpus_run.py`, `calibration.py`, `execution_checks.py` and `probe_execution.py` (opt-in sandbox checks) |
| `operations/` | Read-only `harness readiness` and `harness model-connectivity` checks |
| `qualification/broker/` | Operator broker qualification runners (`python -m infosec_harness.qualification.broker.<module>`); never imported by serving code |
| `api/`, `cli.py` | FastAPI service and contracts; the Typer CLI |
| `intake/`, `integrations/` | Input adapters and Azure DevOps integration |
| `config/`, `skills/`, `tools/` | Packaged model catalogue and reference broker catalog, runtime skills, tool policies |

| `inference/` subpackage | Modules |
| --- | --- |
| `wire/` | `protocol`, `auth`, `codec`, `http_service`, `diagnostics`, `timing`: the `ih-inference-v1` schema and shared HTTP plumbing |
| `catalog/` | `profiles`, `policy`: broker catalog profiles and native policy identity |
| `executor/` | `service`, `compat`, `rendering`: the executor (`python -m infosec_harness.inference.executor`) |
| `worker/` | `transport`, `invocations`, `identity`, `unbound`, `provenance`: the harness worker's client |
| `controller/` | `service`, `admission`, `ledger`, `issuance`, `deployment`: the controller; its factory is `infosec_harness.inference.controller.deployment:controller_factory` |
| `native/` | `openshell`: the OpenShell adapter and lease lifecycle |

| Repository directory | Responsibility |
| --- | --- |
| `ui/` | Frontend source, generated API types and build configuration |
| `tests/` | `agents/` (with the skill lint in `agents/skill_support/`), `runtime/`, `persistence/`, `evals/`, `development/` and `qualification/` (offline regressions for the broker qualification runners); shared fixtures in `tests/conftest.py` |
| `eval-corpus/` | Paired fixture repositories, ground truth and harvested case metadata |
| `evals/` | Committed baselines, sealed held-out sets, calibration plans and agent overlays |
| `docs/` | Living documentation, indexed by `docs/README.md`; dated evidence under `docs/evidence/` |
| `scripts/`, `.claude/skills/` | Developer tools, including the offline exploration measurement library (`scripts/exploration.py`), and development skills (`.agents/skills` is a symlink) |
| `deploy/` | Compose support, egress proxy, dev VM, Kubernetes and OpenShell deployment material |

Runtime data stays inside the Python package so installed wheels work from unrelated working
directories. Repository review material stays outside the wheel. Do not move specs, skills or
migrations into a top-level configuration directory.

## Sources of truth

Agent specs, eval datasets, release policies, the risk scenario library
(`src/infosec_harness/agents/risk-scenarios.yaml`) and the runtime skills are hand-maintained
package data. Edit them in place; tests hold their invariants
(`tests/agents/test_risk_scenarios.py`, `tests/development/test_release_policies.py`,
`tests/agents/test_skills_consistency.py`, `tests/evals/test_eval_coverage.py`). Release gates
exist only in each agent's `src/infosec_harness/agents/<name>/evals/release-policy.yaml`. `CLAUDE.md` imports `AGENTS.md`, and
`.agents/skills` is a symlink to `.claude/skills`, so neither has a copy to drift.

Two artifacts are generated, because their consumers are outside Python:

| Generated artifact | Regenerate | Drift check |
| --- | --- | --- |
| `src/infosec_harness/agents/agent_schema.json` (editor schema for `agent.yaml`) | `just agents-schema` | `tests/agents/test_agents.py` |
| `ui/openapi.json`, `ui/src/api/schema.d.ts` | `just openapi` | `just generated-check` (OpenAPI) and `npm run check:api` in `just ui-check` (client types) |

## Local output ownership

Run repository commands from the checkout root; defaults are relative to the working directory.
Use absolute environment paths when invoking from elsewhere.

| Output | Default location | Owner / override |
| --- | --- | --- |
| Agent eval release reports | `.harness/reports/evals/<experiment-id>.json` | `HARNESS_REPORTS_DIR`; `eval run --report` or `--report-dir` |
| Corpus reports | `.harness/reports/corpus/corpus-<timestamp>.json` | `HARNESS_REPORTS_DIR`; `eval corpus --report` |
| Calibration reports | Explicit `--report` path, conventionally `.harness/reports/calibration/` | `harness eval calibrate` |
| Service validation reports | `.harness/reports/service-validation/` | `./dev validate`, `just validate-services`; `--report` |
| Model connectivity receipt | None unless requested | `--model --connectivity-receipt <path>`; read by the API from `HARNESS_MODEL_CONNECTION_OBSERVATION` |
| Broker qualification reports | `.harness/reports/credential-broker/` | Broker qualification runners; unique run IDs |
| Broker lease state | Operator-owned private lease directory | Controller; retain for reconciliation, never publish |
| Checkout identity and credentials | `.harness/dev.env` | `./dev`; generated, mode 0600 |
| Managed tools and downloads | `.harness/` | `./dev`; pins in `.mise.toml` and `.dev-tools/versions.env` |
| VM state | Short path under `~/.cache/ih/` | `./dev`; recorded in `.harness/runtime-home` |
| Demo database | `.harness/demo.db` | `just demo`, `just migrate`, `just eval-run`; `HARNESS_DATABASE_URL` |
| Repo snapshots, build contexts, artifacts | `.harness/workspace/` | `HARNESS_WORKSPACE_DIR`; S3 replaces the artifact store when configured |
| Environment recipe cache | `.harness/workspace/recipes/` | `HARNESS_RECIPE_CACHE_DIR` |
| Log snapshots | `.harness/logs/compose-*` | Full startup and `./dev logs [SERVICE]` |
| Full-stack database and S3 objects | Checkout compose volumes | Kept by `./dev stop`; deleted only by `./dev reset` |
| Frontend output and dependencies | `ui/dist/`, `ui/node_modules/` | Vite, TypeScript and `npm ci` |

An eval release report's contents are described in
[release evidence](../evaluation/RELEASE_EVIDENCE.md#release-gates). Only complete runs export a
report; a truncated experiment keeps its incremental results in the database. Reports are written
through a same-directory temporary file and an atomic rename, which prevents partial JSON but is
not a power-loss guarantee. `harness report <run-id>` prints to stdout; redirect it under
`.harness/reports/triage/` to keep one.

Committed baselines under `evals/baselines/` and dated folders under `docs/evidence/` are the
only source-controlled evidence ([how evidence is recorded](../evaluation/RELEASE_EVIDENCE.md)).
Do not direct routine output into either. Exports and log snapshots have no automatic retention;
remove them explicitly after review. Never delete the workspace while active or retained runs
reference its snapshots, images, recipes or artifacts.

## Directory conventions

The frontend lives under `ui/`; use `just ui-build` and `just ui-check`. The compose service is
still named `web`, and `HARNESS_WEB_*` settings keep their names. Agent overlays live in
`evals/experiments/overlays/` and typed calibration plans in `evals/experiments/calibration/`;
keep negative results alongside their inputs.

Documents are grouped under `docs/development/`, `docs/architecture/`, `docs/threat-models/`,
`docs/evaluation/`, `docs/operations/` and `docs/broker/`, with `docs/README.md` as the index.
Point-in-time records go to `docs/evidence/<yyyy-mm-dd>-<topic>/` with a short README stating
what they prove and what they do not. `tests/development/test_docs.py` checks that every living
document is indexed and that its links and backticked paths resolve.

CI (`.github/workflows/ci.yml`) calls the same `just` recipes developers run; there is no
separate pre-commit configuration. Tests are grouped by subsystem; pytest discovers all groups
recursively. Keep `dev`, `justfile`,
compose entry points, package manifests and `README.md` at the root. Add a new script to the
[script catalogue](../../scripts/README.md), a new document to the docs index, and a new output
producer to the table above. Outputs default to ignored directories and print their path.
