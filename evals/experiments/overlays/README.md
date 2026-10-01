# Historical agent overlays

These YAML files override selected agent spec fields with `harness eval run --overlay`.
They retain experiment context and negative results; an unsuccessful candidate is not dead code.

```bash
uv run harness eval run probe-planner --overlay evals/experiments/overlays/probe_planner_low_thinking.yaml --repeat 3
uv run harness eval run verdict --overlay evals/experiments/overlays/verdict_forced_reason.yaml --repeat 3
```

Configure the model backend and database explicitly for live experiments. Defaults can make paid
provider calls; the offline component path uses `HARNESS_MODEL_MODE=stub`. Complete reports go to
`.harness/reports/evals/`, while case results remain in the configured database.

Typed calibration plans live in `evals/experiments/calibration/`. See the
[repository guide](../../../docs/development/REPOSITORY_GUIDE.md) for directory conventions.
