# Developer scripts

Prefer the root `./dev` and `just` commands. These scripts support those entry points and are
not the packaged harness runtime.

| Scripts | Purpose / entry point |
| --- | --- |
| `broker_hold_closure.py` | Explicit frozen-manifest dry run/operator loss acceptance; full reserved-envelope charge, immutable unknown tombstones, no model/lifecycle calls; [runbook](../docs/architecture/CREDENTIAL_BROKER_RUNBOOK.md#explicit-conservative-closure-of-retained-unknown-holds) |
| `broker_ledger_check.py` | Ledger concurrency and abrupt-recovery checks on a uniquely named temporary PostgreSQL database; zero provider dispatches; sanitized report under `.harness/reports/credential-broker/` |
| `broker_service_check.py` | Real HTTPS controller/executor processes, PostgreSQL and optional (`--temporal`) Temporal broker qualification against a counted local mock provider; native lifecycle is an explicit fake from `infosec_harness.qualification.broker.service`; runs the env-gated `tests/runtime/test_broker_{service,temporal}_integration.py` |
| `broker_real_provider_check.py` | Frozen-manifest direct / native LocalOps / native Temporal real-provider pilot (`infosec_harness.qualification.broker.pilot`); endpoint and model are manifest inputs; inference only with `--manifest-sha256` and `--allow-inference`; see [deployment](../deploy/openshell/README.md#authorized-local-provider-qualification) |
| `broker_real_graph_check.py` | Freeze, then execute once by digest, one production Temporal graph trial per pilot and phase (`infosec_harness.qualification.broker.graph`) |
| `openshell_controller_configuration.py` | Pure comparison of saved Docker configuration for operator recovery; no lifecycle actions; see [deployment](../deploy/openshell/README.md#comparing-a-recorded-controller-configuration) |
| `openshell_artifacts.py`, `openshell_guest.py` | Verified pinned artifacts and dedicated OpenShell guest runtime ownership/invariant checks; see [deployment](../deploy/openshell/README.md) |
| `dev_setup.py` | Installs every `.mise.toml` tool (Python, uv, Node, just, Temporal CLI) and checks exact versions; checkout identity, ports, managed VM; VM stop, confirmed reset and orphaned-home gc; `./dev`, `./dev stop --vm`, `./dev reset`, `./dev gc` |
| `dev_sandbox_check.py` | Actual sandbox/build-egress fixtures; `./dev doctor` or `./dev smoke` |
| `ui_deployment_smoke.py` | GET-only deployed contracts, operational views, same-origin proxy and actual UI assets; `./dev reload-ui` or explicit API/web origins; creates no findings or model requests |
| `service_validation.py` | Aggregate sanitized readiness report; `./dev validate` / `just validate-services`; inference only with `--model`, optional exact-profile UI receipt |
| `runtime_readiness.py` | Read-only database/schema and Temporal poller checks using configured connectors; no worker import or workflow dispatch; run inside the worker by `service_validation.py` |
| `model_connectivity.py` | Explicit single structured-output request to the configured direct OpenAI-compatible verdict backend; no retries, findings or broker actions; run inside the worker by `service_validation.py --model` |
| `dev_setup_smoke.py` | API/UI/storage readiness and Temporal demonstration; `./dev smoke` |
| `check_api_schema.py` | Check committed OpenAPI against FastAPI; `just generated-check` |
| `conformance.py` | Playbook conformance through external `agentctl`; `just conformance [/path/to/playbooks/tools/agentctl]` |
| `measure_exploration.py` | Offline repository read-tool round trips; `just measure` |
| `measure_cache_prefix.py` | Offline prompt-prefix stability; `just measure` |
| `measure_batch_schedule.py` | Offline scheduling/cache measurements; `just measure` |
| `harvest_vul4j.py` | External corpus metadata import; see [corpus sources](../docs/evaluation/CORPUS_SOURCES.md) |

See [output ownership](../docs/development/REPOSITORY_GUIDE.md#local-output-ownership) before adding a writer.
Keep downloaded tools, credentials, snapshots and run reports out of source directories.
