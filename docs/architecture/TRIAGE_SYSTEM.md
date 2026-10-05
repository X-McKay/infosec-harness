# The triage system: how the agents compose

Triage pre-identified vulnerability findings for exploitability: profile the repository, build
it, author and run a unit-test probe in an isolated sandbox, and return a three-way verdict
decided from a deterministic oracle signal.

Most of what the multi-agent playbook asks a System Spec to declare already exists here as
*code*: the pydantic-graph topology in `graph/triage.py`, the repair budgets in each
`agent.yaml`, the verdict contract in `agents/validators.py`. This page states the composition
in prose so it can be reviewed; it is not a second source of truth, and where it and the code
disagree, the code is what runs. Member versions, skills, toolsets and budgets are read from
`src/infosec_harness/agents/<name>/agent.yaml`.

## Members

| Agent | Role | Required | Max calls per finding | Output |
| --- | --- | --- | --- | --- |
| intake | normalizer | no | 1 | ExtractedFinding |
| recon | profiler | yes | 1 (per repo@revision) | RepoProfile |
| env-planner | environment planner | yes | 1 | EnvironmentSpec |
| build-repair | environment repairer | no | 6 | EnvironmentSpec |
| partial-build | environment repairer | no | 4 | EnvironmentSpec |
| context | investigator | yes | 1 | FindingContext |
| probe-planner | probe planner | yes | 1 | ProbePlan |
| probe-author | probe author | yes | 1 | ProbeSource |
| probe-repair | probe author | no | 3 | ProbeSource |
| probe-diagnosis | execution judge | yes | 4 | ProbeDiagnosis |
| verdict | verdict judge | yes | 1 | Verdict |

"Required" means a finding cannot reach a verdict without it. The repair agents are optional
because a build or probe that works first time never invokes them.

## Topology

A programmatic pipeline. The orchestrator is deterministic code, not an agent: the graph
decides every transition, dispatches each agent with typed evidence it assembled, and records
what comes back. No agent delegates to another, membership is fixed, and delegation depth is
zero. There is deliberately no coordinator agent, which is the strongest form of the
playbook's "deterministic control, probabilistic collaboration".

## Why a multi-agent system

**Claimed benefits.**

- Capability isolation: only the environment agents may run shell commands in the sandbox,
  and only the probe agents author executed code. A single agent holding every tool would put
  code execution behind every prompt.
- Context segregation: the verdict is decided by an agent that never sees the repository, only
  the recorded evidence, so it cannot substitute an impression of the code for the oracle
  signal.
- Independent review: probe-diagnosis judges an execution without having written the probe,
  which is what lets a defective probe be told apart from a genuine negative.
- Separately governed responsibilities: the agents that determine executed code carry a
  critical governance tier and their own controls; the analysis agents do not.

**Baseline that could refute it.** A single conforming agent holding every skill and tool,
prompted to triage a finding end to end and emit the same Verdict, scored on the same corpus
with the same deterministic oracle and verdict contract.

**Success measures.** The multi-agent system's false-negative rate on truly exploitable corpus
cases is no worse than the single-agent baseline's, with the sandbox enabled. Cost per correct
verdict is within 2x of the baseline's. Neither can claim `potentially_exploitable` without an
oracle signal, since the contract is deterministic in both.

## Data flow

- Every agent receives typed evidence assembled by the orchestrator, never another agent's
  transcript. No agent sees another's history and no credentials are forwarded.
- Repository content, finding text, and probe output are untrusted data wherever they appear,
  and are labelled as such in the prompt that carries them.
- Nothing an agent emits becomes shared truth until the orchestrator records it.

| Artifact | Readers | Note |
| --- | --- | --- |
| repo snapshot | recon, env-planner, build-repair, partial-build, context, probe-author, probe-repair | read-only, confined to the snapshot root by the tool layer |
| probe source | probe-diagnosis, probe-repair | model-authored code; executed only inside the sandbox |
| probe execution | probe-diagnosis, verdict | markers are detected deterministically, never by a model |
| verdict | nobody downstream | rejected by a deterministic validator if the facts do not support it |

Egress: none at probe time; a registry allowlist at build time; the tracker write-back is
comment-only and never edits or closes an item.

## Termination

| Rule | When | Outcome |
| --- | --- | --- |
| verdict reached | the verdict agent returns a contract-valid verdict | complete |
| unreachable by context | context cites code making the sink unreachable | complete, `likely_not_exploitable`, no probe is built |
| test or vendored code | the finding is in test or vendored code | complete, `likely_not_exploitable` |
| probe unrepairable | probe repairs are exhausted and the last diagnosis is `probe_defect` | complete, `inconclusive` |
| environment unbuildable | the build and its repairs fail, including the partial-build fallback | complete, `inconclusive` |
| budget exhausted | a member exceeds its declared run budget | stop, `inconclusive` |
| contract unsatisfiable | the verdict agent cannot satisfy the evidence contract within its retries | stop, `inconclusive` |

`inconclusive` is a success state, not a failure: it is how the absence of evidence is reported
rather than being rounded to "not exploitable". It is also the escalation state.

**Conflict.** The deterministic verdict contract is the arbiter. Where a model's conclusion and
the recorded facts disagree, the facts win and the verdict is rejected; the system never
resolves a conflict by preferring the more confident agent.

## Limits

Per-member ceilings are the `metadata.budgets` in each spec, enforced through `UsageLimits` in
both the local and durable paths. A finding makes at most 24 agent runs (the sum of the max
calls above), with no parallel agents and one pass per finding; repairs are bounded per
interaction rather than by rounds. The system's own ceiling is the sum of its members'.
