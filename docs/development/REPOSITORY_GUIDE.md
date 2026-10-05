# Repository guide

## Where to change things

Paths below are relative to `src/infosec_harness/` unless they start at the repository root.

| Module | Responsibility |
| --- | --- |
| `domain/models.py`, `domain/canonical.py` | Typed findings, plans, verdicts and shared contracts; canonical JSON bytes and SHA-256 digests |
| `agents/` | Agent specs, eval datasets and release policies (`agents/<name>/`), the risk scenario library, the registry (agent bindings and `EXECUTION_GENERATION`), model factory, capabilities, prompt renderer (`render.py`), repository read tools (`repo_tools.py`), budgets, stubs and validators |
| `graph/triage.py`, `graph/prepare.py` | The per-finding triage graph and component preparation |
| `graph/pipeline.py`, `graph/workloads.py` | Grouping, scheduling and per-finding orchestration, and the build/smoke/probe workloads, shared by the in-process and durable paths |
| `graph/ops.py`, `graph/manifests.py`, `graph/scoring.py` | The execution interface, secret-free reproduction manifests, prioritization |
| `workflows/workflows.py`, `workflows/activities.py`, `workflows/worker.py` | Temporal workflows (`TriageBatch`, `ComponentPreparation`, `FindingTriage`), activities and the worker |
| `workflows/submission.py`, `workflows/local_run.py`, `workflows/writeback.py` | Durable submission and cancellation; in-process stub runs; Azure DevOps comment write-back |
| `workflows/accounting.py`, `workflows/progress.py` | Root budget reservations and persisted progress |
| `sandbox/docker.py`, `sandbox/policy.py`, `sandbox/process.py` | gVisor Docker runner, the runtime gate, and the one owned subprocess runner for Docker, Git and native CLIs; `sandbox/k8s.py` only renders Pod specs |
| `repo/` | Hardened Git checkout under `local_repo_roots`, access checks, component and stack detection |
| `persistence/` | Run store (`store.py`, `db.py`), migrations, artifacts, budgets, recipe cache, reconciliation; `identity.py` (worker-host provenance), `paths.py` (workspace layout), `population.py` (demo/eval/operational populations) |
| `inference/` | Opt-in credential broker: protocol, admission, ledger, controller, executor and OpenShell adapter |
| `evals/` | `run.py` and `adapters.py` (eval runs), `dataset.py` (the one dataset loader), `gates.py` (the one release-gate evaluator), `release_report.py`, `metrics.py`, `messages.py` (captured-message walker), `pricing.py`, `overlays.py`, `baselines.py`, `corpus_run.py`, `calibration.py`, `inert_gates.py` |
| `operations/` | Read-only `harness readiness` and `harness model-connectivity` checks |
| `qualification/broker/` | Operator broker qualification runners (`python -m infosec_harness.qualification.broker.<module>`); never imported by serving code |
| `api/`, `cli.py` | FastAPI service and contracts; the Typer CLI |
| `intake/`, `integrations/` | Input adapters and Azure DevOps integration |
| `config/`, `skills/`, `tools/` | Packaged model catalogue and reference broker catalog, runtime skills, tool policies |

| Repository directory | Responsibility |
| --- | --- |
| `ui/` | Frontend source, generated API types and build configuration |
| `tests/` | `agents/`, `runtime/`, `persistence/`, `evals/`, `development/` and `qualification/` (offline regressions for the broker qualification runners); shared fixtures in `tests/conftest.py` |
| `eval-corpus/` | Paired fixture repositories, ground truth and harvested case metadata |
| `evals/` | Committed baselines, sealed held-out sets, calibration plans and agent overlays |
| `docs/` | Living documentation, indexed by `docs/README.md`; dated evidence under `docs/evidence/` |
| `scripts/`, `.claude/skills/` | Developer tools and development skills (`.agents/skills` is a symlink) |
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
| Frontend output and cache | `ui/dist/`, `ui/node_modules/.cache/` | Vite and TypeScript |

An eval release report carries `run` (status, split, `n` of `n_planned`, the case-set digest and
dataset path), the policy verdict `gate_evaluation`, and `inert_checks` (policy checks that could
not have failed for this run). Only complete runs export a report; a truncated experiment keeps
its incremental results in the database. Reports are written through a same-directory temporary
file and an atomic rename, which prevents partial JSON but is not a power-loss guarantee.
`harness report <run-id>` prints to stdout; redirect it under `.harness/reports/triage/` to keep
one.

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
