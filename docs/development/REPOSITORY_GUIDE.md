# Repository guide

## Where to change things

| Directory | Responsibility |
| --- | --- |
| `src/infosec_harness/domain/` | Typed findings, plans, verdicts and shared contracts |
| `src/infosec_harness/agents/` | Agent loading, configuration, capabilities, budgets, stubs and per-agent specs/evals |
| `src/infosec_harness/graph/` | Preparation and triage orchestration, scoring and execution interfaces |
| `src/infosec_harness/workflows/` | Temporal activities, workflows, scheduling and recovery |
| `src/infosec_harness/repo/` | Checkout, access checks, stack and component detection |
| `src/infosec_harness/sandbox/` | Docker execution, isolation policy and evidence; Kubernetes specification rendering only |
| `src/infosec_harness/persistence/` | Run store, accounting, artifacts, recipe cache and migrations |
| `src/infosec_harness/evals/` | Dataset adapters, scoring, reports, comparison, provenance and calibration |
| `src/infosec_harness/api/`, `cli.py` | API contracts and command entry points |
| `src/infosec_harness/intake/`, `integrations/` | Input adapters and Azure DevOps integration |
| `src/infosec_harness/config/`, `skills/`, `tools/` | Packaged model catalogue, runtime guidance and tool policies |
| `ui/` | Frontend source, generated API types and build configuration |
| `tests/` | Regression cases grouped into agents, runtime, persistence, evals and development |
| `eval-corpus/` | Paired fixture repositories, ground truth and harvested case metadata |
| `evals/` | Accepted baselines, system release policy and calibration inputs |
| `evals/experiments/overlays/`, `calibration/` | Historical agent overlays and typed calibration plans |
| `systems/`, `docs/` | Reviewable system contracts, governance and developer documentation |
| `scripts/`, `dev-skills/` | Developer tools and canonical development skills |
| `deploy/` | Compose infrastructure configuration, proxy and Kubernetes manifests |

Runtime data stays inside the Python package so installed wheels work from unrelated working
directories. Repository review material stays outside the wheel. Avoid moving specs, skills or
migrations into a top-level configuration directory.

## Local output ownership

Run repository commands from the checkout root. Defaults are relative to the working directory;
an installed CLI uses that same convention. Use absolute environment paths when invoking from
another directory. The launcher always switches to its own checkout.

| Output | Default location | Owner / override |
| --- | --- | --- |
| Checkout identity and local credentials | `.harness/dev.env` | `./dev`; generated, mode 0600 |
| Managed tools and downloads | `.harness/` | Launcher; pinned versions in `.mise.toml` and `.dev-tools/versions.env` |
| VM state | Short path under `~/.cache/ih/` | Launcher; actual location recorded in `.harness/runtime-home` |
| Demo database | `.harness/demo.db` | `just demo`, `migrate`, `eval-run`; `HARNESS_DATABASE_URL` |
| Repo snapshots and build contexts | `.harness/workspace/` | `HARNESS_WORKSPACE_DIR` |
| Filesystem artifacts | `.harness/workspace/artifacts/` | Workspace; S3 replaces this store when configured |
| Environment recipe cache | `.harness/workspace/recipes/` | `HARNESS_RECIPE_CACHE_DIR` or workspace |
| Completed agent release reports | `.harness/reports/evals/exp-<id>.json` | `HARNESS_REPORTS_DIR`; `eval run --report` and sweep `--report-dir` override |
| Log snapshots | `.harness/logs/compose-*` | Successful full startup and `./dev logs [service]`; 100 lines per selected service |
| Continuous container logs | Managed VM Docker storage | Compose logging driver; 10 MiB × 3 files per service |
| Full-stack database and S3 objects | Checkout compose volumes | Managed project identity; not the demo SQLite database |
| Frontend output and cache | `ui/dist/`, `ui/node_modules/.cache/` | Vite and TypeScript |
| Python caches | `.venv/`, `.pytest_cache/`, `.ruff_cache/`, `__pycache__/` | Tool-managed and ignored |

Each automatic eval report uses the experiment id, so repeated runs retain separate evidence.
Only complete runs export release reports; truncated experiments retain incremental results in
the database. Explicit report paths can intentionally replace earlier exports. Reports publish
through a same-directory temporary file and atomic replacement. This prevents partial JSON;
it does not promise power-loss durability. Export failure propagates while completed database
results remain queryable. Atomic exports and log snapshots use private files.

`harness report <run-id>` and corpus evaluation still print to stdout. For a retained triage
export, choose the location explicitly:

```bash
mkdir -p .harness/reports/triage
uv run harness report <run-id> > .harness/reports/triage/<run-id>.json
```

Calibration deliberately requires an explicit `--report` path; use `.harness/reports/calibration/`.
Committed baselines under `evals/baselines/` and reviewed evidence under `docs/validation/` are
intentional source-controlled records. Do not direct routine output into those directories.

`./dev stop` preserves volumes and VM state. Log snapshots and report exports have no automatic
retention deletion: remove unwanted exports explicitly after review. Never delete the entire
workspace while active or retained runs reference snapshots, images, recipes or artifacts.
Container log rotation does not rotate exported snapshots. `just down-reset` is the explicitly
destructive manual compose command; it is not the managed launcher's cleanup operation.

## Generated sources

| Generated artifact | Source / regeneration | Drift check |
| --- | --- | --- |
| `CLAUDE.md` | `AGENTS.md`; `just generated-sync` | `just generated-check` |
| `.agents/skills/`, `.claude/skills/` | `dev-skills/`; `just dev-skills-sync` | `just dev-skills-check` |
| Risk assessments | `scripts/risk_scenarios.py`; `just governance` | Relevant governance tests |
| Release policies and system spec | Governance generators in `scripts/`; `just governance` | Relevant release/system tests |
| Generated runtime skill regions | `scripts/skill_specs.py`; `just governance` | Skill consistency tests |
| Agent JSON schema | Agent spec schema; `just agents-schema` | Agent schema and packaging tests |
| `ui/openapi.json`, `ui/src/api/schema.d.ts` | FastAPI contracts; `just openapi` | `just generated-check` for OpenAPI; CI regenerates client and checks diff |

Read the [script catalogue](../../scripts/README.md) before running generators. `just generated-sync`
only syncs instructions and development skills; it does not regenerate every artifact above.

## Directory conventions

The frontend lives under `ui/`. Use `just ui-build` and `just ui-check`; `web-build` and
`web-check` remain compatibility aliases. The Compose service is still named `web`, and existing
`HARNESS_WEB_*` settings and volumes retain their names, so checkout state is preserved.

Agent spec overlays live in `evals/experiments/overlays/`; typed calibration plans live in
`evals/experiments/calibration/`. Preserve negative experiment results alongside their inputs.

Documents are grouped under `docs/development/`, `docs/architecture/`, `docs/evaluation/` and
`docs/validation/`, with `docs/README.md` as the entry point. Generated risk assessments and
threat models retain their contracted locations. Imported qualification plans and reviews live under `docs/evaluation/`; fixes and retained
qualification reports live under `docs/validation/`. `docs/development/HANDOFF.md` preserves the
imported development checkpoint. The separately authored credential-broker proposal at
`docs/CREDENTIAL_BROKER_SPEC.md` is left in place to preserve concurrent work.

Tests are grouped under `tests/agents/`, `tests/runtime/`, `tests/persistence/`, `tests/evals/`
and `tests/development/`. Shared fixtures stay in `tests/conftest.py`. Pytest discovers all groups
recursively; repository path calculations in moved tests account for the extra directory level.

Keep `dev`, `justfile`, compose entry points, package manifests and `README.md` at the root.
Add a new script to the script catalogue, a new document to the docs index, and a new output
producer to this table. Outputs should default to ignored state directories and identify their
path in command output; generators should update declared source-controlled destinations only.
