# Evaluation configuration and accepted results

| Location | Contents |
| --- | --- |
| `baselines/` | Explicitly accepted, committed agent/model results; [recording rules](baselines/README.md) |
| `experiments/calibration/` | Typed calibration plans (`harness eval calibrate`) |
| `experiments/overlays/` | Agent spec overlays, each pinned to the spec version it was written against |
| `heldout/` | Sealed held-out datasets, run with `harness eval run <agent> --dataset` |
| `../eval-corpus/` | Paired fixture repositories and ground truth |
| `../src/infosec_harness/agents/<name>/evals/` | Packaged per-agent datasets and release policies (the only definition of release gates) |
| `../src/infosec_harness/evals/` | Evaluation implementation |

`harness eval run <agent>...` (or `--all`) records case results incrementally in
`HARNESS_DATABASE_URL` (`.harness/local.db` when unset), prints one summary table, and exports a
release report per run to
`.harness/reports/evals/<experiment-id>.json` (`HARNESS_REPORTS_DIR`, `--report` or
`--report-dir` select another location). The report carries the policy's own verdict
(`gate_evaluation`, `not_checked` when a `required_provenance` key is missing), the checks that
could not have failed for this run (`inert_checks`, also printed beside the report path), what
the numbers are over (`run`: split, `n` of `n_planned`, repetitions, the case-set digest) and
what produced them (`provenance`). Truncated runs export no report. `just eval` runs every
agent on stub models, as CI does, and `harness eval release` is the qualification run for a
release ([release evidence](../docs/evaluation/RELEASE_EVIDENCE.md#qualifying-a-release)). `--dataset PATH` runs another dataset (a sealed held-out set)
against the deployed spec; such a run is labelled `split: external`. Stub scores exercise
adapters and never establish live-model quality.

`harness eval corpus` runs the paired ground-truth corpus end to end (`--manifest`, `--limit`,
`--dataset`) and writes a report under `.harness/reports/corpus/` (`--report` selects another).

Calibration plans and agent overlays use different schemas. See `harness eval calibrate --help`
for calibration; reports require an explicit path, conventionally `.harness/reports/calibration/`.
Transient outputs stay under ignored `.harness/`; this directory contains reviewed inputs and
accepted agent baselines. Other accepted evidence lives in dated folders under
[`docs/evidence/`](../docs/evidence/README.md); see
[release evidence](../docs/evaluation/RELEASE_EVIDENCE.md). Directory conventions are in the [repository guide](../docs/development/REPOSITORY_GUIDE.md).
