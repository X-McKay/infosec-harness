# Tests

Run the complete deterministic suite from the repository root with `just test`.
Pytest discovers all subdirectories; shared stub mode, database, recipe and report isolation
remain in `conftest.py`.

| Directory | Coverage |
| --- | --- |
| `agents/` | Agent configuration, models, budgets, capabilities, skills, validation and prompt costs |
| `runtime/` | Graphs, workflows/recovery, sandbox boundaries, repository detection, API and telemetry |
| `persistence/` | Run store, artifacts, migrations, recipes and metric lifecycle |
| `evals/` | Datasets, calibration, reporting, provenance, corpus, harvesting and trajectories |
| `development/` | Onboarding, packaging, repository layout, generated governance and conformance contracts |
| `qualification/` | Offline regressions for the operator broker qualification runners in `infosec_harness.qualification.broker`: manifest scope, source/configuration preflight, baseline comparison, phase claims, graph freezing and child-process cleanup |

For focused work:

```bash
uv run pytest tests/agents
uv run pytest tests/runtime/test_sandbox_policy.py
uv run pytest tests/development/test_dev_experience.py
```

Fixtures containing paths such as `web/app.js` or `tests/test_probe.py` describe synthetic target
repositories; those names are independent of this harness's own directory layout. Do not rewrite
them when reorganizing the harness.

Optional Temporal integration checks need a real service or the Temporal CLI as described in
[local setup](../docs/development/LOCAL_SETUP.md). Broker service and native qualification tests
in `runtime/` are marked `requires_service(...)` and skip unless their operator runner supplies the
named manifest variable: `scripts/broker_service_check.py` sets `HARNESS_BROKER_SERVICE_MANIFEST`,
and the native Temporal acceptance runner needs `HARNESS_NATIVE_TEMPORAL_CONFIG`.

Packaging tests build and install a wheel into an isolated environment, resolving the declared
dependency ranges independently of `uv.lock`.
