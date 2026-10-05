# Release gates and how evidence is recorded

Accepted evidence has exactly two homes:

| Evidence | Home | Recorded by |
| --- | --- | --- |
| An agent's accepted eval result per model | `evals/baselines/<agent>/<tier>.json` | `harness eval release --save-baselines` or `harness eval baseline save --latest <agent>`, reviewed in a pull request |
| Everything else: live qualification runs, sandbox and runtime checks, broker qualification, UI validation | `docs/evidence/<yyyy-mm-dd>-<topic>/` | A dated folder with a README stating what it proves and what it does not |

Everything else is transient: the experiment store (`HARNESS_DATABASE_URL`, `.harness/local.db`
when unset) holds every run and case result, and reports under `.harness/reports/` belong to one
checkout.

## Qualifying a release

```bash
harness eval release --save-baselines            # every agent, each on its own model tier
harness eval release -m opus --agent verdict     # restrict the tier or the agents
```

The qualification run refuses stub models and a working tree that is dirty or has no commit,
before any model is called. It then runs every agent's full packaged dataset, sequentially, on
the live model, evaluates each agent's release policy, and prints one table (agent, model,
status, `n` of `n_planned`, task success, gate status, failing checks, report path). Reports and
a `summary.json` go to `.harness/reports/release/<commit>/` (under `HARNESS_REPORTS_DIR`). It
exits 1 unless every run completed and every policy is `passed`. With `--save-baselines`, each
passing run is recorded under `evals/baselines/` after all runs finish, through the same
baseline rules and refusals as `harness eval baseline save`; commit those files.

The execution-backed gates need a host whose sandbox actually executes, which means `runsc`
(the `./dev` VM, or a worker host with gVisor). Without one, `build-repair`'s execution checks
are `not_checked` and its `execution_not_checked_count` hard gate fails: that is by design, as
an unexecuted check is not a pass, and the release is not qualified on such a host.

To record the evidence, copy the sanitized `summary.json` (and any reports a reviewer needs)
into a dated folder as described in [writing an evidence folder](#writing-an-evidence-folder),
and commit it with the baselines.

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
`average_cost_usd` is likewise the one cost metric; the API's experiment summary exposes both
under those names and the UI shows "accuracy" only as a display label. The evaluator identity
recorded in every report is `deterministic-agent-output-v13`.
Most agents' floor was lowered from 0.85 at the owner's explicit request on 2026-09-29: it is a
quality-policy decision, not evidence of better agents, and it does not relax any other gate or
regrade an earlier result ([agent-quality evidence](../evidence/2026-09-30-agent-quality/README.md)).
`tests/development/test_release_policies.py` holds the policy invariants.

`harness eval run <agent>...` (or `--all`) writes one release report per run to
`.harness/reports/evals/` and prints one summary table; it exits 1 when a run does not complete,
and with `--require-gates` also when a policy is not `passed`. Each fact is
recorded once: `run` says what the numbers are over (status, split, `n` of `n_planned`,
repetitions, the case-set digest) and `provenance` what produced them (commit, agent version,
config hash, model, dataset and its version, experiment id). The report also carries the
policy verdict `gate_evaluation` and `inert_checks`: policy checks that could not have failed
for this run. Every report is audited for inert checks as it is written and the audit is printed
beside its path; inertness is evidence quality, not a gate, and there is no separate re-audit
command. Complete experiments also store `gate_evaluation` and a `status` in the experiment
record, which the API exposes as `ExperimentSummary.status` and the UI shows as the release-gate
row.

Declared sandbox execution checks run through `src/infosec_harness/evals/execution_checks.py`.
A fixture image that fails to build because the builder infrastructure failed is `not_checked`;
one whose declared environment fails to build is `failed`. Probe-writing evals use structural
scoring and claim no independent target attestation. Candidate-forgeable in-process tracing
has been retired; it supplied no release-gate evidence.

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
