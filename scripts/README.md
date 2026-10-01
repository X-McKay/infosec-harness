# Developer scripts

Prefer the root `./dev` and `just` commands. These scripts support those entry points and are
not the packaged harness runtime.

| Scripts | Purpose / entry point |
| --- | --- |
| `broker_ledger_check.py`, `broker_service_check.py` | Isolated PostgreSQL, real HTTPS and optional Temporal broker qualification; sanitized reports under `.harness/reports/credential-broker/` |
| `openshell_artifacts.py`, `openshell_guest.py` | Verified pinned artifacts and dedicated OpenShell guest runtime ownership/invariant checks; see [deployment](../deploy/openshell/README.md) |
| `dev_setup.py` | Pinned tools, checkout identity, ports and managed VM setup; `./dev` |
| `dev_sandbox_check.py` | Actual sandbox/build-egress fixtures; `./dev doctor` or `./dev smoke` |
| `dev_setup_smoke.py` | API/UI/storage readiness and Temporal demonstration; `./dev smoke` |
| `sync_dev_instructions.py` | Generate `CLAUDE.md` from `AGENTS.md`; `just generated-sync` / `generated-check` |
| `sync_dev_skills.py` | Canonical skill digests and client copies; `just dev-skills-sync` / `dev-skills-check` |
| `check_api_schema.py` | Check committed OpenAPI against FastAPI; `just generated-check` |
| `gen_risk_assessments.py`, `risk_scenarios.py` | Generated agent risk assessments and their source scenarios |
| `gen_release_policies.py` | Generated per-agent/system release policies |
| `gen_system_spec.py` | Generated system spec and delegation/data-flow/termination policies |
| `restructure_skills.py`, `skill_specs.py` | Runtime skill metadata/marked sections and their canonical specifications |
| `conformance.py` | Playbook conformance through external `agentctl`; `just conformance` |
| `measure_exploration.py` | Offline repository read-tool round trips; `just measure` |
| `measure_cache_prefix.py` | Offline prompt-prefix stability; `just measure` |
| `measure_batch_schedule.py` | Offline scheduling/cache measurements; `just measure` |
| `harvest_vul4j.py` | External corpus metadata import; see [corpus sources](../docs/evaluation/CORPUS_SOURCES.md) |

`just governance` runs the governance generators, including runtime skill regeneration.
Review its diff: source-controlled generated artifacts are distinct from transient reports.
The script name `restructure_skills.py` is historical, but it is an active, idempotent generator.

See [output ownership](../docs/development/REPOSITORY_GUIDE.md#local-output-ownership) before adding a writer.
Keep downloaded tools, credentials, snapshots and run reports out of source directories.
