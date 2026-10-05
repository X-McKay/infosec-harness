# Evaluation configuration and accepted results

| Location | Contents |
| --- | --- |
| `qualification/` | Reviewed component measurement references, scoped dependency hashes and exact equivalence reviews |
| `baselines/` | Explicitly accepted, committed agent/model results; [recording rules](baselines/README.md) |
| `experiments/calibration/` | Typed calibration plans (`harness eval calibrate`) |
| `experiments/overlays/` | Agent spec overlays, each pinned to the spec version it was written against |
| `heldout/` | Sealed held-out datasets, run with `harness eval run <agent> --dataset` |
| `../eval-corpus/` | Paired fixture repositories and ground truth |
| `../src/infosec_harness/agents/<name>/evals/` | Packaged per-agent datasets and release policies (the only definition of release gates) |
| `../src/infosec_harness/evals/` | Evaluation implementation |

Run `just eval-run` for a stub agent dataset. `harness eval run <agent>` records case results
incrementally in `HARNESS_DATABASE_URL` and exports a release report to
`.harness/reports/evals/<experiment-id>.json` (`HARNESS_REPORTS_DIR`, `--report` or
`--report-dir` select another location). The report carries the policy's own verdict
(`gate_evaluation`), the checks that could not have failed for this run (`inert_checks`), and
what the numbers are over: split, `n` of `n_planned`, the case-set digest and the dataset path.
Truncated runs export no report. `--dataset PATH` runs another dataset (a sealed held-out set)
against the deployed spec; such a run is labelled `split: external`. Stub scores exercise
adapters and never establish live-model quality.

`harness eval corpus` runs the paired ground-truth corpus end to end (`--manifest`, `--limit`,
`--dataset`) and writes a report under `.harness/reports/corpus/`.

Calibration plans and agent overlays use different schemas. See `harness eval calibrate --help`
for calibration; reports require an explicit path, conventionally `.harness/reports/calibration/`.
Transient outputs stay under ignored `.harness/`; this directory contains reviewed inputs and
accepted records. Directory conventions are in the [repository guide](../docs/development/REPOSITORY_GUIDE.md).
