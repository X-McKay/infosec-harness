# Agent overlays

These YAML files override selected agent spec fields with `harness eval run --overlay`. Each
agent entry declares the `base_version` (the spec's `metadata.version`) it was written against,
and the loader refuses an overlay whose base no longer matches the committed spec: applied to a
later spec, an overlay measures a different change than the one it records.

```bash
harness eval run probe-planner --overlay evals/experiments/overlays/probe_planner_low_thinking.yaml --repeat 3
```

Recorded negative results whose overlays went stale and were removed:

- `verdict_forced_reason` (written against an earlier verdict spec): spelling out the `inconclusive_reason` rule
  instead of a flat menu of values, after `inconclusive_env` returned invalid output about a
  third of the time. Its overlay replaced the whole instruction block and would revert every
  verdict instruction change since; re-derive it from the current spec to retest.

Configure the model backend and database explicitly for live experiments. Defaults can make paid
provider calls; the offline component path uses `HARNESS_MODEL_MODE=stub`. Complete reports go to
`.harness/reports/evals/`, while case results remain in the configured database.

Typed calibration plans live in `evals/experiments/calibration/`. See the
[repository guide](../../../docs/development/REPOSITORY_GUIDE.md) for directory conventions.
