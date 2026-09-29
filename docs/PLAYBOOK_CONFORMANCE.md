# Playbook conformance

This system is built to the [Agent Playbook](https://github.com/X-McKay/playbooks/tree/main/agent-playbook)
and the [Multi-Agent Systems Playbook](https://github.com/X-McKay/playbooks/tree/main/multi-agent-playbook).
Conformance is checked, not asserted:

```bash
just conformance                                  # needs agentctl on PATH
just conformance AGENTCTL=/path/to/playbooks      # or a checkout of that repo
```

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
See `src/infosec_harness/resources.py` and `tests/test_packaging.py`, which builds the real
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

**`tests/` is flat.** No `unit/integration/workflow/replay/security` split. All five kinds
exist and are named in the filenames; partitioning them would move ~45 files and change no
contract.

**No `activities/`, `runtime/`, `observability/` or `policy/` packages.** Activities are one
module (`workflows/activities.py`), observability is `telemetry.py`, and policy is split
between `tools/policies.py` and `agents/governance.py`. Each is currently a file's worth of
code; promoting a file to a package before it needs to be one adds a directory, not structure.

**No `.agents/skills/`.** That path is reserved for coding-agent instructions, and this
repository has none.

**The capability bill of materials is a hash, not a manifest.** `config_hash` covers the
effective spec, every skill's contents, and the resolved model, and it appears in traces
(`agent.config_hash`), in the persisted run records, in eval-report provenance, and on
`GET /api/config`. What the playbook asks for additionally is a manifest *object* enumerating
its fields — contract version, execution class, governance tier, risk-assessment digest,
instruction hashes, output-schema hash, budget policy, worker and build version — with its own
ID. Every one of those fields is inside the spec the hash covers, so nothing is unattributable
today; what a reader cannot do is expand the hash without the checkout. Worth building.

## The release gates, run live

Measured against the live model with budgets enforced (`harness eval run <agent> --report`,
then `agentctl release check`):

| agent | task success | schema validity | budget breaches | unevidenced safety | gate |
| --- | --- | --- | --- | --- | --- |
| `context` | 100% (7/7) | 1.0 | 0 | 0 | **pass** |
| `probe-diagnosis` | 100% (7/7) | 1.0 | 0 | 0 | **pass** |
| `verdict` | 67% (2/3) | 0.67 | 0 | 0 | **fail** |

Two things worth reading off that table.

No run hit its budget, so the ceilings brake runaway execution without constraining healthy
work — which is what a budget is for. And `unevidenced_safe_verdicts` is 0 everywhere: no agent
claimed safety on evidence that could not support it.

`verdict` fails its own gate, and should. Its `inconclusive_env` case still omits the
contract-required `inconclusive_reason` about a third of the time, exhausts its retries, and
returns no valid output — the residual issue recorded in `LIVE_VALIDATION.md`. The gate catching
it is the point: this is a real defect being blocked, not a threshold set to flatter. In
production the graph fallback turns it into an `inconclusive` verdict rather than a lost
finding, so the failure is contained; it is still a failure.

## What conformance does and does not establish

It establishes that the contracts are complete and internally consistent: every agent has an
owner, a governance tier that matches its risk assessment, an execution class its tools
justify, a per-run budget that is enforced, an eval dataset, and an executable release gate.

It does not establish that the system is safe to launch. Five agents and the system carry
`conditional_go`, not `go`, because the control that bounds their largest risk — gVisor — has
never executed. `agentctl risk validate` is satisfied by an assessment that records this
honestly; it is `CONDITION-001` that remains open. See
[`LIVE_VALIDATION.md`](LIVE_VALIDATION.md).

## Not adopted

The playbook's `human_governed` execution class, approval policies, tenant isolation, and
authorization scopes are not implemented, because nothing here needs them: every tool is
read-only or sandbox-confined, there is no consequential write (the tracker write-back is
comment-only), and the deployment is single-tenant. They would be required before this system
could take an action on anyone's behalf.
