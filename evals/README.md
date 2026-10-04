# Evaluation configuration and accepted results

| Location | Contents |
| --- | --- |
| `qualification/` | Reviewed component measurement references, scoped dependency hashes and exact equivalence reviews |
| `baselines/` | Explicitly accepted, committed agent/model results; [recording rules](baselines/README.md) |
| `experiments/calibration/` | Typed calibration plans, currently `verdict-tool-budget.yaml` |
| `systems/triage-system/` | Generated system release policy |
| `experiments/overlays/` | Historical agent spec overlays; preserve recorded negative results |
| `../eval-corpus/` | Paired fixture repositories and ground truth |
| `../src/infosec_harness/agents/<name>/evals/` | Packaged per-agent datasets and release policies |
| `../src/infosec_harness/evals/` | Evaluation implementation |

Run `just eval-run` for a stub agent dataset. `harness eval run <agent>` records case results
incrementally in `HARNESS_DATABASE_URL` and exports a complete release report to
`.harness/reports/evals/<experiment-id>.json`. Use `HARNESS_REPORTS_DIR`, `--report`, or a model
sweep's `--report-dir` to select another export location. Truncated runs cannot export release
reports. Stub scores exercise adapters and never establish live-model quality.

Calibration plans and agent overlays use different schemas. See `harness eval calibrate --help`
for calibration; reports require an explicit path, conventionally `.harness/reports/calibration/`.
Transient outputs stay under ignored `.harness/`; this directory contains reviewed inputs and
accepted records. Directory conventions are in the [repository guide](../docs/development/REPOSITORY_GUIDE.md).
