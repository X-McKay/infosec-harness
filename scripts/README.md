# Developer scripts

Prefer the root `./dev` and `just` commands. These scripts support those entry points and are
not the packaged harness runtime.

| Scripts | Purpose / entry point |
| --- | --- |
| `broker_ledger_check.py`, `broker_service_check.py` | Isolated PostgreSQL, real HTTPS and optional Temporal broker qualification; sanitized reports under `.harness/reports/credential-broker/` |
| `openshell_controller_configuration.py` | Pure comparison of saved Docker configuration for operator recovery; mount order only is canonicalized and recorded default OOM representation checked; no lifecycle actions |
| `openshell_artifacts.py`, `openshell_guest.py` | Verified pinned artifacts and dedicated OpenShell guest runtime ownership/invariant checks; see [deployment](../deploy/openshell/README.md) |
| `qualification_ledger.py` | File-only dependency assessment of Git-reviewed component evidence; [workflow](../docs/evaluation/COMPONENT_QUALIFICATION.md) |
| `dev_setup.py` | Pinned tools, checkout identity, ports and managed VM setup; `./dev` |
| `dev_sandbox_check.py` | Actual sandbox/build-egress fixtures; `./dev doctor` or `./dev smoke` |
| `ui_deployment_smoke.py` | GET-only deployed contracts, operational views, same-origin proxy and actual UI assets; `./dev reload-ui` or explicit API/web origins; creates no findings or model requests |
| `service_validation.py` | Aggregate sanitized readiness report; `./dev validate` / `just validate-services`; inference only with `--model`, optional exact-profile UI receipt |
| `runtime_readiness.py` | Read-only database/schema and Temporal poller checks using configured connectors; no worker import or workflow dispatch |
| `model_connectivity.py` | Explicit single structured-output request to the configured direct OpenAI-compatible verdict backend; no retries, findings or broker actions |
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

## Comparing a recorded controller configuration

`openshell_controller_configuration.py` is an importable operator validation utility.
It does not inspect Docker, load credentials, start containers, or establish ownership.
Use `configuration_digest(saved_inspect)` to compare the complete `Config`, `HostConfig`,
`Mounts`, and `NetworkSettings` projection. Both mount-record arrays are sorted; all
other configuration values remain exact. Keep inspection files private because `Config`
can contain credentials.

`validate_replacement_host_config(old_host_config, new_host_config, created=True)`
checks a newly created replacement against an explicitly recorded old null
`OomKillDisable`. A created replacement must have boolean false. With `created=False`,
the running replacement may have null or boolean false, reflecting Docker's default
and unsupported-option representation. True, numeric zero, missing fields, and every
other HostConfig difference are rejected. The actual running OOM value remains part
of the configuration digest; later health checks compare that recorded value exactly.

Before using either result for recovery, independently authenticate the exact issued
container IDs, process identity, source and image pins, mounts, TLS, and retained state.
A matching digest grants no permission to start, adopt, retry, release, or delete anything.

Run `pytest tests/development/test_openshell_controller_configuration.py` for the pure
regressions. Serving code, executor images, model controls, budgets, and durable workflow
identities are unaffected; this utility requires no replay generation change.
