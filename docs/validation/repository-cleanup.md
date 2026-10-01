# Repository cleanup review — 2026-10-01

## Scope and findings

Reviewed Python runtime modules and their references, developer tooling, frontend configuration,
local output producers, CI commands and developer-facing documentation. No unrelated working-tree
changes existed at the start. This is a conservative cleanup, not a proof that every dynamic or
externally imported entry point is unused.

Removed helpers with no repository callers or dynamic registration:

- `ModelsConfig.tier_for_policy`: active resolution uses the model-policy mapping directly.
- `registry.agent_run_budgets`: durable execution uses resolved agent configuration.
- `store.run_config_signature`: persisted configuration provenance uses manifests.
- `Measurement.calls_per_request`: no measurement/report consumes this property.
- `ui/tsconfig.node.json`: no project references or build entry points use it.

Retained CLI commands, API handlers, Pydantic validators, migrations, compatibility re-exports,
active governance generators, paired fixtures and historical negative experiment results. Being
invoked indirectly or recording an unsuccessful experiment is not evidence of dead code.

Corrected stale model-config paths, fixed-port managed-stack claims, manual-compose onboarding,
Kubernetes submission claims, development-skill and manifest claims, and historical validation
language. Added documentation entry points and a module/output/generated-source map. The later directory migration is documented in `repository-reorganization.md`;
current directory conventions are in [REPOSITORY_GUIDE.md](../development/REPOSITORY_GUIDE.md).

## Affected contracts and risks

Completed per-agent evals now export by default to
`HARNESS_REPORTS_DIR/evals/<experiment-id>.json`, defaulting to `.harness/reports/`.
Explicit report paths and model-sweep directories keep their existing behavior. Report JSON
schema, metrics, thresholds, truncation refusal and baseline promotion requirements are unchanged.
There is no automatic promotion. Corpus evals and triage reports still print to stdout, and
calibration retains its explicit report argument.

Reports publish atomically through private temporary files. Normal exceptions clean up temporary
files and preserve prior evidence; abrupt process termination can leave a temporary file.
Power-loss durability is not claimed. An export failure propagates, but the completed experiment
is already persisted and can be queried. Default names preserve each new experiment; explicit
paths retain intentional replacement semantics. No automatic report/snapshot deletion is added.

Successful managed full startup and `./dev logs [service]` save private, unique snapshots under
`.harness/logs/`. Compose failures remain nonzero through `pipefail`. Managed container logs rotate
at 10 MiB with three files per service. Snapshot capture is bounded to 100 lines per service;
exported snapshots require explicit retention cleanup. Logging changes take effect when managed
containers are recreated. No actual Docker log-driver behavior was exercised in this review.

TypeScript build metadata goes to ignored `ui/node_modules/.cache/`. Existing local workspace,
database, snapshot, artifact and VM locations are unchanged, so no state migration is needed.

## Version, replay and recovery assessment

No workflow topology, activity names, inputs, retries, cancellation semantics, sandbox boundary,
database migration, verdict contract or release-report schema changes. No Temporal patch marker,
agent behavior version, evaluator version or provenance-schema bump is required for auxiliary
exports and removal of uncalled helpers. Source/config digests naturally identify changed code.
The package remains `2.0.0.dev0`; the release owner should include these changes in its next release.
External consumers importing the removed undocumented helpers would need to update; this review
establishes no in-repository callers, not absence of consumers outside the repository.

Eval retries still create a new experiment id and report, rather than overwriting an earlier
run. Incremental database persistence and truncated/cancelled-run handling remain intact. Report
export runs outside Temporal and creates no replay I/O. Log snapshots are launcher operations.
Existing workflow histories and retained artifact refs need no migration; no workspace cleanup or
volume reset was performed. Fail-closed isolation and validation expectations are unchanged.

## Check evidence

| Gate | Status | Evidence / limitation |
| --- | --- | --- |
| `just check` | passed | Ruff, compilation and all agent specs; existing locked venv, `UV_NO_SYNC=1` and checkout-local UV cache |
| `just generated-check` | passed | OpenAPI, shared instructions and development skill drift |
| `just dev-skills-check` | passed | Both generated development skill copies match canonical sources |
| Focused cleanup tests | passed | 32 tests across developer experience, eval model sweep, release reports and truncation; includes new log snapshot test |
| `just test` | failed | Host-permission run: 1,509 passed, 11 skipped, two installed-wheel dependency failures; full run preceded the additional log snapshot test, which passed in the focused run |
| Frontend checks | passed | Formatting, two search tests, TypeScript and production Vite build (`npm run format:check`, `npm run build`) |
| Shell syntax | passed | `bash -n dev`; snapshot function executed with fake compose success/failure, private unique files and bounded arguments |
| Local documentation links / whitespace | passed | Changed Markdown relative file targets checked; `git diff --check` |
| Actual managed stack / log rotation | not_checked | No containers or VM started/recreated; full-profile isolation fixtures not rerun |
| Live provider / clean-host acceptance | not_checked | No model calls or fresh-host onboarding |
| Temporal integration | not_checked | 11 optional integration tests skipped; no Temporal service exercised |
| External playbook conformance | not_checked | Generated and deterministic governance checks run; external agentctl not invoked |
| Database/state migration | not_applicable | No schema or durable state location changes |

The sandboxed first full run had 1,502 passes, two denied loopback binds and seven packaging
setup errors from restricted dependency downloads. Host permissions resolved those environmental
errors; the remaining two failures are real dependency compatibility failures.

The wheel fixture resolves the declared dependency ranges independently of `uv.lock`. It selected
`pydantic==2.13.5`, `pydantic-ai-slim==2.52.0` and `temporalio==1.34.0`; the locked development
environment uses `pydantic==2.13.5`, `pydantic-ai-slim==2.49.0` and `temporalio==1.33.0`.
`test_every_agent_builds_from_the_installed_wheel` and
`test_skills_resolve_to_the_package_not_the_working_directory` fail during schema generation for
`temporalio.workflow._event_groups.EventGroup`. Unmodified `HEAD` source reproduces the same error
with that installed dependency set; local diagnostic output is at
`.harness/reports/cleanup/baseline-dependency-failure.log`. Expectations and dependency ranges were
not weakened. Follow up by testing supported dependency combinations and fixing the integration
or deliberately narrowing the supported ranges with release evidence; do not hide the failure by
making this packaging test use the development environment.
