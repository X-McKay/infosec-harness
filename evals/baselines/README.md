# Accepted eval results

One file per agent per model: `evals/baselines/<agent>/<model-tier>.json`.

These are committed. That is the whole point of them.

Every run lands in the experiment store, and that is the right place for *all* of them —
queryable, incremental, cheap to write. It is the wrong place for the few that matter later.
That database is a local scratch file in practice; it is not reviewed, it does not travel with
a clone or a release, and the number you want six weeks from now — *what did `verdict` score on
sonnet before we changed the prompt* — is exactly the one that is gone.

So the two roles are split, the way
[agent-playbook 02](https://github.com/X-McKay/playbooks/blob/main/agent-playbook/02-reference-architecture.md)
lays the directories out:

| | holds | lifetime |
| --- | --- | --- |
| experiment store (`HARNESS_DATABASE_URL`) | every run, every case result | local, disposable |
| `evals/baselines/` | the accepted result per agent per model | committed, reviewed |

## Recording one

```bash
harness eval run verdict -m sonnet
harness eval baseline save exp-<id>
```

Two refusals are enforced rather than documented, because a baseline that quietly lies is worse
than no baseline — it becomes the thing every later comparison is measured against:

- **A truncated run is refused.** Its metrics cover only the cases that happened to run, so
  pinning one silently redefines the denominator.
- **A dirty working tree is refused.** The recorded SHA would name a commit that never
  contained the code that produced the numbers, and nothing downstream could detect it.

## Reading them

```bash
harness eval baseline list            # with a note wherever the code has moved since
harness eval compare --agent verdict  # latest run per model, from the store
```

Each file carries the commit, the distribution version, the resolved model id, the config hash,
the dataset version, and the cost basis (`priced` / `zero_priced` / `stub` / `unknown_model`).
The cost basis is not decoration: a self-hosted model with a declared zero rate always "wins"
on cost against a billed one, for a reason that has nothing to do with either model.
