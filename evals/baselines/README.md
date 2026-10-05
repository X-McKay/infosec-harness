# Accepted eval results

One file per agent per model: `evals/baselines/<agent>/<model-tier>.json`.

These are committed. That is the whole point of them.

Every run lands in the experiment store, and that is the right place for *all* of them —
queryable, incremental, cheap to write. It is the wrong place for the few that matter later.
The database is configured by `HARNESS_DATABASE_URL`; local commands use `.harness/local.db`.
It is not reviewed and does not travel with a clone or a release, and the number you want six weeks from now — *what did `verdict` score on
sonnet before we changed the prompt* — is exactly the one that is gone.

So the two roles are split, the way
[agent-playbook 02](https://github.com/X-McKay/playbooks/blob/main/agent-playbook/02-reference-architecture.md)
lays the directories out:

| | holds | lifetime |
| --- | --- | --- |
| experiment store (`HARNESS_DATABASE_URL`) | every run, every case result | configured database; retained per deployment policy |
| `evals/baselines/` | the accepted result per agent per model | committed, reviewed |

## Recording one

```bash
harness eval run verdict -m sonnet
harness eval baseline save --latest verdict -m sonnet   # or: harness eval baseline save exp-<id>
```

`--latest` picks the newest complete live run of that agent and tier over the full dataset
(`-m` defaults to the agent's own tier). `harness eval release --save-baselines` records every
passing agent at once, under the same rules.

These refusals are enforced rather than documented, because a baseline that quietly lies is
worse than no baseline — it becomes the thing every later comparison is measured against:

- **A run not recorded as complete is refused** (truncated, still running, or with no status).
  Its metrics cover only the cases that happened to run, so pinning one silently redefines the
  denominator.
- **A run over less than the full dataset is refused** (a calibration or held-out split, or a
  `--dataset` run). A baseline promises the agent's whole packaged dataset.
- **A stub-model run is refused.** It exercises the eval machinery and measures no agent.
- **A dirty working tree, or a run with no commit, is refused.** The recorded SHA would name a
  commit that never contained the code that produced the numbers.

## Reading them

```bash
harness eval baseline list            # with a note wherever the code has moved since
harness eval compare --agent verdict  # latest run per model, from the store
```

Each file carries the commit, the distribution version, the resolved model id, the config hash,
the dataset version, and the cost basis (`priced` / `zero_priced` / `stub` / `unknown_model`).
The cost basis is not decoration: a self-hosted model with a declared zero rate always "wins"
on cost against a billed one, for a reason that has nothing to do with either model.

Completed `harness eval run` invocations also export release reports under
`.harness/reports/evals/<experiment-id>.json` by default. These ignored local reports retain
individual runs; saving an accepted baseline remains an explicit, reviewed action. A truncated
experiment remains in the database and does not produce a release report.
