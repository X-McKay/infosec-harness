# Playbook conformance

This system is built to the [Agent Playbook](https://github.com/X-McKay/playbooks/tree/main/agent-playbook)
and the [Multi-Agent Systems Playbook](https://github.com/X-McKay/playbooks/tree/main/multi-agent-playbook).
Conformance is checked, not asserted:

```bash
just conformance                                  # needs agentctl on PATH
just conformance /path/to/playbooks      # or a checkout of that repo
```

Historical validator output (not a current-tree acceptance result):

```
PASS agents   errors=0 waived=11 warnings=22
PASS skills   errors=0 waived= 0 warnings= 0
PASS risk     errors=0 waived= 0 warnings=22
PASS system   errors=0 waived=11 warnings=24
```

`scripts/conformance.py` mirrors the repository into the layout `agentctl` discovers and runs
its four validators against the real YAML. The warnings are the ones that should be there: the
risk assessments are drafts with open questions, and a draft cannot satisfy production
readiness until a named owner accepts it.

## Where the artifacts live

Everything an agent needs in order to run is package data under `src/infosec_harness/`, so it
ships in the wheel; everything reviewers read *about* the system stays at the repository root.

| Artifact | Path | Ships? | Source of truth |
| --- | --- | --- | --- |
| Agent Specs | `src/infosec_harness/agents/<name>/agent.yaml` | yes | hand-authored |
| Skills | `src/infosec_harness/skills/<name>/SKILL.md` | yes | `scripts/skill_specs.py` → `restructure_skills.py` |
| Model catalogue | `src/infosec_harness/config/models.yaml` | yes | hand-authored |
| Tool policies | `src/infosec_harness/tools/<toolset>/tool.yaml` | yes | hand-authored |
| Eval datasets | `src/infosec_harness/agents/<name>/evals/dataset.yaml` | yes | hand-authored |
| Release policies | `src/infosec_harness/agents/<name>/evals/release-policy.yaml` | yes | `scripts/gen_release_policies.py` |
| Risk assessments | `docs/risk-assessments/` | no | `scripts/risk_scenarios.py` → `gen_risk_assessments.py` |
| System Spec | `systems/triage-system/` | no | `scripts/gen_system_spec.py` |
| Threat model | `docs/threat-models/triage-system.md` | no | hand-authored |

`just governance` regenerates everything derived. Tests assert the committed files match, so
the generators cannot drift from what is reviewed.

## Deliberate deviations

**Directory naming.** Agent and system directories are named as the agents are named
(`probe-author`), while `agentctl` expects the module-normalized form (`probe_author`), and a
durable system is expected to have an `activities/` package beside `workflows/` where ours is
one module. `scripts/conformance.py` renames on the way into a throwaway mirror; the YAML it
validates is the real file.

This used to be a much larger deviation — specs, skills and the model catalogue sat at the
repository root, described here as "a difference in filing, not in contract". That was wrong,
and measurably so. The playbook's Build and packaging section makes package data a MUST, and
the filing was exactly what broke it: the wheel shipped none of the three, `REPO_ROOT` was
`Path(__file__).parents[2]` (the repository root only when imported from `src/`), and the
`Skills` capability was handed a bare relative `skills` that resolved against the process
working directory. An installed copy could not construct a single agent. The whole in-tree
suite passed throughout, because in-tree every one of those accidents happens to be true.
See `src/infosec_harness/resources.py` and `tests/development/test_packaging.py`, which builds the real
wheel, installs it, and asserts all 11 agents construct from an unrelated directory.

**`retries` as a mapping** (waived, 11 agents). `agentctl` requires a plain integer.
pydantic-ai's own Agent Spec schema accepts an integer *or* an `AgentRetries` mapping — see
`agents/agent_schema.json`, generated from the framework — and the mapping is what lets
`verdict` carry `output: 4` while its tool retries stay at 2. Collapsing it would lose a
distinction the framework supports and the retry-bound calculation relies on. Worth raising
upstream.

**A shared threat model.** Each agent's spec points at
`docs/threat-models/triage-system.md` rather than a per-agent document, because the trust
boundaries are system-level: the same untrusted repository reaches all of them, and the same
sandbox contains the code. Eleven near-identical documents would be worse, not better.

## Where eval results live

Two stores, because they answer different questions and a single one does neither well.

| | holds | lifetime | tied to |
| --- | --- | --- | --- |
| experiment store (`HARNESS_DATABASE_URL`) | every run, every case result | deployment retention policy | commit + dirty flag, model, config hash |
| `evals/baselines/<agent>/<tier>.json` | the accepted result per agent per model | committed, reviewed | the commit it was measured at |

The database is where runs go: incremental, queryable, and written after every case so a run
killed halfway keeps what it scored. The offline demo uses `.harness/demo.db`; managed services use PostgreSQL. Neither store is
reviewed in Git or distributed with a clone. So the handful of numbers that matter later are
promoted into the repository, one file per agent per model, reviewed in a pull request like any
other change and readable without the database that produced them.

Every row and every file records what agent-playbook 02 needs to make a number attributable:
the commit, **whether that commit's tree was clean**, the distribution version, the resolved
model id and tier, the backend, the config hash, the dataset version, and the cost basis.

Three of those are worth their own note.

**`git_dirty`.** `git rev-parse HEAD` answers the same SHA whether or not the tree matches it,
so a run over uncommitted edits used to be filed against a commit that never contained the code
it measured, with nothing downstream able to tell. `harness eval baseline save` refuses such a
run outright, as it refuses a truncated one: a baseline that quietly lies is worse than no
baseline, because it becomes the thing every later comparison is read against.

**The model, as columns rather than only inside `config_hash`.** The hash fingerprints the
model but cannot be grouped by, filtered on, or read, so "how did `verdict` do on opus" was not
a question the store could answer however many times it had been run.

**The cost basis** (`priced` / `zero_priced` / `stub` / `unknown_model`), read from the same
estimator the eval loop uses. A self-hosted model with a declared zero rate always "wins" on
cost against a billed one, for a reason that has nothing to do with either model, and after the
fact there is no way to tell which kind of zero a zero was. `harness eval compare` says so
rather than letting the column be read straight.

```bash
harness eval run verdict -m sonnet -m opus -m haiku   # one dataset, three models, one table
harness eval compare --agent verdict                  # the same, asked after the fact
harness eval baseline save exp-<id>                   # promote an accepted result
```

## Where the structure still differs from the reference architecture

Audited against
[02-reference-architecture](https://github.com/X-McKay/playbooks/blob/main/agent-playbook/02-reference-architecture.md).
These are open, with the reason each is currently judged not worth closing. None of them is a
MUST.

**Per-agent `factory.py` / `dependencies.py` / `models.py` / `instructions/`.** The golden path
gives each agent its own module for these; ours are shared — one `registry.py` builds all 11
from their specs, one `deps.py`, one `models.py`, and instructions are written inline in
`agent.yaml`. Eleven factories differing only in a name would be eleven places for a
governance check to be forgotten. Revisit if any agent needs construction logic of its own.

**Agent-private skills.** The playbook colocates a capability with its agent until more than
one agent uses it. Of 25 skills, 24 are enabled by 3–5 agents each; exactly one —
`partial-build` — is enabled by a single agent and by that rule belongs under it. It stays in
the shared library because every spec already scopes itself with an explicit `include:` list,
which is the isolation the rule exists to give, and a second discovery root would be a real
cost for one directory.

**`evals/` is split rather than a single tree.** The playbook groups
`datasets/evaluators/experiments/fixtures/baselines`. Ours are placed by what they belong to:
datasets and release policies beside the agent they grade (so they ship, and a release check
can run against the wheel), evaluators in `src/infosec_harness/evals/`, fixtures in
`eval-corpus/`. `agentctl release check` discovers them where they are.

**Tests are grouped by subsystem.** Agent, runtime, persistence, evaluation and development
checks use shared root fixtures. The directory conventions are recorded in
[REPOSITORY_GUIDE.md](../development/REPOSITORY_GUIDE.md#directory-conventions).

**No `activities/`, `runtime/`, `observability/` or `policy/` packages.** Activities are one
module (`workflows/activities.py`), observability is `telemetry.py`, and policy is split
between `tools/policies.py` and `agents/governance.py`. Each is currently a file's worth of
code; promoting a file to a package before it needs to be one adds a directory, not structure.

## Implemented development and provenance structure

Canonical development skills live under `dev-skills/`; `.agents/skills/` and `.claude/skills/`
are generated discovery copies. `just dev-skills-check` prevents drift. These are distinct from
packaged runtime skills.

`graph/manifests.py` builds persisted harness, repository, environment and capability manifests.
They carry versioned runtime/policy digests and resolved agent configuration; the implementation
and `tests/runtime/test_snapshot_integrity.py` establish the current fields. The manifest is persisted
with triage output rather than represented solely by an opaque configuration hash.

Completed agent evals automatically export reports under `.harness/reports/evals/`; these
transient reports are separate from committed accepted baselines.

## Historical live release-gate measurements

The earlier live validation recorded the following results with budgets enforced (`harness eval run <agent> --report`,
then `agentctl release check`):

| agent | task success | schema validity | budget breaches | unevidenced safety | gate |
| --- | --- | --- | --- | --- | --- |
| `context` | 100% (7/7) | 1.0 | 0 | 0 | **pass** |
| `probe-diagnosis` | 100% (7/7) | 1.0 | 0 | 0 | **pass** |
| `verdict` | 67% (2/3) | 0.67 | 0 | 0 | **fail** |

Two things worth reading off that table.

No measured run hit its budget; this sample alone does not validate runaway-execution braking. And `unevidenced_safe_verdicts` is 0 everywhere: no agent
claimed safety on evidence that could not support it.

The historical `verdict` result failed its own gate. Its `inconclusive_env` case omitted the
contract-required `inconclusive_reason` about a third of the time, exhausts its retries, and
returns no valid output — the residual issue recorded in `LIVE_VALIDATION.md`. The gate catching
it is the point: this is a real defect being blocked, not a threshold set to flatter. In
production the graph fallback turns it into an `inconclusive` verdict rather than a lost
finding, so the failure is contained; it is still a failure.

## What conformance does and does not establish

It establishes that the contracts are complete and internally consistent: every agent has an
owner, a governance tier that matches its risk assessment, an execution class its tools
justify, a per-run budget that is enforced, an eval dataset, and an executable release gate.

Conformance does not establish actual runtime isolation or release readiness. Current and
historical execution evidence, remaining clean-host acceptance gaps, and real versus mocked
checks are distinguished in [IMPLEMENTATION_VALIDATION.md](../validation/IMPLEMENTATION_VALIDATION.md).
Re-run runtime fixtures for the deployment being assessed; names and manifests alone are not
execution evidence.

## Not adopted

The playbook's `human_governed` execution class, approval policies, tenant isolation, and
authorization scopes are not implemented, because nothing here needs them: every tool is
read-only or sandbox-confined, there is no consequential write (the tracker write-back is
comment-only), and the deployment is single-tenant. They would be required before this system
could take an action on anyone's behalf.
