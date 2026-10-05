# Tests

Run the complete deterministic suite from the repository root with `just test`.
Pytest discovers all subdirectories; shared stub mode, database, recipe and report isolation
remain in `conftest.py`.

| Directory | Coverage |
| --- | --- |
| `agents/` | Agent configuration, models, budgets, capabilities, skills, validation and prompt costs; `agents/skill_support/` holds the skill lint the skill evals import |
| `runtime/` | Graphs, workflows/recovery, sandbox boundaries, repository detection, API and telemetry |
| `persistence/` | Run store, artifacts, migrations, recipes and metric lifecycle |
| `evals/` | Datasets, calibration, reporting, provenance, corpus, harvesting and trajectories |
| `development/` | Onboarding, packaging, repository layout, documentation links, release policies and conformance contracts |
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

Markers gate what a test needs; `tests/conftest.py` owns every gating decision:

| Marker | Meaning |
| --- | --- |
| `requires_temporal` | Starts a local Temporal dev server from the pinned CLI; skips without it, fails instead under `HARNESS_TEST_REQUIRE_TEMPORAL=1` (set by `./dev test` and CI) |
| `requires_service(...)` | Needs an explicit operator qualification runner; skips unless every named variable is set |
| `network` | Needs PyPI or GitHub; excluded from `just test`, run by `just test-network` and `just test-all` |
| `posix` | Needs POSIX process semantics |

The session refuses an ambient `HARNESS_MODEL_MODE` other than `stub` unless
`HARNESS_TEST_ALLOW_LIVE=1`, and uses a per-process SQLite database unless
`HARNESS_TEST_DATABASE_URL` names another. Broker service and native qualification tests in
`runtime/` are marked `requires_service(...)` and run only when their operator runner supplies the
named variable: `scripts/broker_service_check.py` sets `HARNESS_BROKER_SERVICE_MANIFEST`,
and the native Temporal acceptance runner needs `HARNESS_NATIVE_TEMPORAL_CONFIG`.

Packaging tests build and install a wheel into an isolated environment, resolving the declared
dependency ranges independently of `uv.lock`.
