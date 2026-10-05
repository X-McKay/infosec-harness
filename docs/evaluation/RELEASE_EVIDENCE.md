# Release gates and how evidence is recorded

Accepted evidence has exactly two homes:

| Evidence | Home | Recorded by |
| --- | --- | --- |
| An agent's accepted eval result per model | `evals/baselines/<agent>/<tier>.json` | `harness eval baseline save <experiment-id>`, reviewed in a pull request |
| Everything else: live qualification runs, sandbox and runtime checks, broker qualification, UI validation | `docs/evidence/<yyyy-mm-dd>-<topic>/` | A dated folder with a README stating what it proves and what it does not |

Everything else is transient: the experiment store (`HARNESS_DATABASE_URL`) holds every run and
case result, and reports under `.harness/reports/` belong to one checkout.

## Release gates

An agent's release gates are defined only in its
`src/infosec_harness/agents/<name>/evals/release-policy.yaml`, and
`src/infosec_harness/evals/gates.py` is the only code that evaluates them. A policy names hard
gates (the metric must equal the limit) and thresholds (`min` or `max`). A check whose metric is
missing or not a number is `not_checked`, never `passed`, and a policy with any such check has
not been cleared. The policy's `required_provenance` keys (commit, agent version, config hash,
model, dataset version) are enforced too: a missing or empty key leaves an evaluation with no
failed check `not_checked`, and is listed in `gate_evaluation.missing_provenance`.

Every hard-gate set includes `schema_validity_rate: 1.0` and `budget_exhausted_count: 0`; budget
behavior is gated by that count alone. `task_success_rate` is the one pass rate an agent eval
reports (there is no separate `accuracy`), and its floor is `min: 0.75` for every agent.
Most agents' floor was lowered from 0.85 at the owner's explicit request on 2026-09-29: it is a
quality-policy decision, not evidence of better agents, and it does not relax any other gate or
regrade an earlier result ([agent-quality evidence](../evidence/2026-09-30-agent-quality/README.md)).
`tests/development/test_release_policies.py` holds the policy invariants.

`harness eval run <agent>` writes a release report to `.harness/reports/evals/`. Each fact is
recorded once: `run` says what the numbers are over (status, split, `n` of `n_planned`,
repetitions, the case-set digest) and `provenance` what produced them (commit, agent version,
config hash, model, dataset and its version, experiment id). The report also carries the
policy verdict `gate_evaluation` and `inert_checks`: policy checks that could not have failed
for this run. Every report is audited for inert checks as it is written and the audit is printed
beside its path; inertness is evidence quality, not a gate, and there is no separate re-audit
command. Complete experiments also store `gate_evaluation` and a `status` in the experiment
record, which the API exposes as `ExperimentSummary.status` and the UI shows as the release-gate
row.

The opt-in sandbox execution checks (`src/infosec_harness/evals/execution_checks.py`,
`src/infosec_harness/evals/probe_execution.py`) share one fixture-image helper. A fixture image
that fails to build because the builder infrastructure failed is `not_checked`; one whose
declared environment fails to build is `failed`.

## Baselines

`harness eval baseline save` refuses a run that is not recorded as complete (truncated, still
running, or with no status), one over less than the full packaged dataset (a calibration,
held-out or `--dataset` split), a stub-model run, and a run from a dirty tree or with no commit.
[`evals/baselines/README.md`](../../evals/baselines/README.md) explains the file format and how to
read them.

## Held-out and corpus runs

Run a sealed held-out dataset in place against the deployed spec; nothing is copied:

```bash
harness eval run <agent> --dataset evals/heldout/quality-gates-v1/datasets/<agent>/dataset.yaml
```

The report labels such a run `split: external` and records the dataset path and case-set digest.
`evals/heldout/quality-gates-v1/STAGING.md` is the staging protocol and attempt budget.

`harness eval corpus` scores the paired ground-truth corpus end to end and writes a report under
`.harness/reports/corpus/`. A corpus run approves only its own manifest's directory as a local
repository root; cases that resolve outside it are refused. `--manifest` selects another corpus (for example
`eval-corpus/external/vul4j.json`), `--dataset` labels its source, and `--limit N` scores the
first N cases while keeping vulnerable/fixed pairs together.

Experiment overlays (`harness eval run --overlay`) must declare the `base_version` of each spec
they modify; the loader refuses an overlay whose base no longer matches. Output-retry
classification in reports is `output-retries/v2`.

## Writing an evidence folder

- Name it `docs/evidence/<yyyy-mm-dd>-<topic>/` after the day the measurement was taken, and
  add one line for it to `docs/evidence/README.md`.
- Its README is one paragraph: what was measured, at which commit, what it proves, and what it
  does not. Report every gate as `passed`, `failed`, `not_checked`, or justified
  `not_applicable`; a configured runtime or provider name is never execution evidence.
- Commit only reproducible, secret-free material: summaries, sanitized reports and digests. Do
  not commit absolute paths from one machine, private endpoints, credentials or source-bearing
  model payloads; describe a private artifact by its SHA-256 instead.
- Never edit a folder afterwards to match newer code. A later measurement gets a new folder,
  and failed or truncated runs are kept rather than replaced.

A reviewed component qualification ledger with dependency hashes and equivalence reviews was
removed on 2026-10-04: its records named absolute paths on one workstation and could not be
reassessed anywhere else. The service no longer reports component qualification
([qualification dashboard](../operations/QUALIFICATION_DASHBOARD.md)); the
measurements the ledger referenced remain in
[the broker qualification checkpoint](../evidence/2026-10-04-broker-qualification-checkpoint/README.md).
