# The triage system: how the agents compose

Triage pre-identified vulnerability findings for exploitability: profile the repository, build
it, author and run a unit-test probe in an isolated sandbox, and return a three-way verdict
decided from a deterministic oracle signal.

Most of what the multi-agent playbook asks a System Spec to declare already exists here as
*code*: the pydantic-graph topology in `src/infosec_harness/graph/triage.py`, the repair
budgets in `src/infosec_harness/settings.py` and each `agent.yaml`, the verdict contract in
`src/infosec_harness/runtime/validators.py`. This page states the composition
in prose so it can be reviewed; it is not a second source of truth, and where it and the code
disagree, the code is what runs. Member versions, skills, toolsets and budgets are read from
`src/infosec_harness/agents/<name>/agent.yaml`.

## Members

| Agent | Role | Required | Max calls per finding | Output |
| --- | --- | --- | --- | --- |
| intake | normalizer | no | 1 | ExtractedFinding |
| recon | profiler | yes | 1 (per repo@revision) | RepoProfile |
| env-planner | environment planner | yes | 1 | EnvironmentSpec |
| build-repair | environment repairer | no | 6 at preparation, plus 1 probe-time environment repair | EnvironmentSpec |
| partial-build | environment repairer | no | 4 | EnvironmentSpec |
| context | investigator | yes | 1 | FindingContext |
| probe-planner | probe planner | yes | 1 | ProbePlan |
| probe-author | probe author | yes | 1 | ProbeSource |
| probe-repair | probe author | no | 3 | ProbeSource |
| probe-diagnosis | execution judge | yes | 5 (one per probe execution) | ProbeDiagnosis |
| verdict | verdict judge | yes | 1 | Verdict |

"Required" means a finding cannot reach a verdict without it. The repair agents are optional
because a build or probe that works first time never invokes them.

## Topology

A programmatic pipeline. The orchestrator is deterministic code, not an agent: the graph
decides every transition, dispatches each agent with typed evidence it assembled, and records
what comes back. No agent delegates to another, membership is fixed, and delegation depth is
zero. There is deliberately no coordinator agent, which is the strongest form of the
playbook's "deterministic control, probabilistic collaboration".

Within an invocation, agents choose their observations and tool turns under the declared
request, tool, token and cost ceilings. Build repair has no fixed halfway cutoff that removes
its tools. Probe validators enforce path and evidence-marker contracts; they do not infer
whether a test ran from source-language substrings. The sandbox's positive and negative
controls verify the runner, and observed execution markers govern definitive verdicts.

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
- Repository content, finding text, and probe output are untrusted data wherever they appear.
  See [prompt construction](#prompt-construction) for how the renderer keeps them from
  forging prompt structure.
- Nothing an agent emits becomes shared truth until the orchestrator records it.

| Artifact | Readers | Note |
| --- | --- | --- |
| repo snapshot | recon, env-planner, build-repair, partial-build, context, probe-author, probe-repair | read-only, confined to the snapshot root by the tool layer |
| probe source | probe-diagnosis, probe-repair | model-authored code; executed only inside the sandbox |
| probe execution | probe-diagnosis, verdict | markers are detected deterministically, never by a model |
| verdict | nobody downstream | rejected by a deterministic validator if the facts do not support it |

Environment skills teach dependency setup, framework selection and output visibility. Sandbox
policy validates image authority, confined paths and the probe addressing contract; successful
build and positive/negative smoke executions establish viability. The runtime binds image
allowlists into resolved agent provenance before durable execution, so output validation does
not reread operator settings while replaying.

Egress: none at probe time or from the sandbox shell tool; at build time only the operator's
allowlisting proxy (`deploy/squid-allowlist.conf`), never a list derived from the repository; the tracker write-back is
comment-only and never edits or closes an item.

## Durable execution

`TriageBatchWorkflow` groups findings by repository, discovers each repository once, splits it
into compatible components, runs `ComponentPreparationWorkflow` once per component, and fans the
component's findings out warm-first as `FindingTriageWorkflow` children so they share the cached
prompt prefix. Grouping, scheduling, the per-finding pipeline and failure records live in
`src/infosec_harness/graph/pipeline.py` and `src/infosec_harness/graph/workloads.py` and are shared
with the in-process path, which runs stub models only; real assessments always run on Temporal.

Workflow type names and agent activity identities carry the execution generation
(`EXECUTION_GENERATION`, currently `v8`). Workflow and activity arguments are typed models
(`src/infosec_harness/workflows/payloads.py`) validated on both sides of the Temporal boundary,
and every activity's retry policy bounds its attempts or names its non-retryable errors
(`src/infosec_harness/workflows/activity_options.py`). There are no retained earlier generations
and no `workflow.patched` branches: a history recorded by an earlier generation is not
replayable, so a deployment drains or terminates in-flight batches first
([service environments](../development/SERVICE_ENVIRONMENTS.md#deploying-a-new-execution-generation)).
Workflow ids are opaque. Each result persists a manifest (`schema_version` 3, assigned in
`src/infosec_harness/persistence/identity.py`) whose environment section records the probe
adapter contract `ADAPTER_CONTRACT_VERSION` (`unit-probe-adapters/v3`, in
`src/infosec_harness/sandbox/profiles.py`) and `adapter_profiles`: `{id, support}` per
recognised ecosystem profile, plus each unmapped language as unsupported.

**Accounting.** Every batch, durable or in-process, is accepted with a root budget ledger that
pins each agent's configuration digest; an agent reservation against a ledger that pins none,
or with a different digest, is refused (`src/infosec_harness/persistence/budgets.py`). There is
no unaccounted mode. A run's usage (`RunTelemetry`, schema 2, in
`src/infosec_harness/persistence/run_telemetry.py`) is complete only when every recorded agent
call has exactly one ledger operation and every one of them settled; otherwise totals stay
unknown rather than zero, with the known part recorded separately. A call that failed but
returned a partial outcome settles as `usage: partial_lower_bound`, which releases nothing from
its reservation. In-process runs reserve nothing in the ledger, so they report their usage as
not fully accounted.

## Prompt construction

`src/infosec_harness/runtime/render.py` is the only path from typed inputs to prompt text. The
layout is stable to volatile (repository context, a cache point, then the finding payload), and
volatile fields are dropped by model and field name, never by bare key, so
`FindingContext.path` (the source-to-sink chain) reaches the probe planner, probe author and
verdict agents. Every value, strings included, is encoded as one line of JSON with `</` written
as `<\/`: payload text cannot contain a raw newline or a closing tag, so the only section markers
in a prompt are the renderer's.

The repository read tools in `src/infosec_harness/tools/repository.py` are confined to the
snapshot and byte-capped per call. `search_code` runs its regular expression in a child process
(`sys.executable -I -S`) that is killed at a deadline, so the worker must be able to spawn its
own interpreter. `repo_digest` treats a directory as test code when any whole path segment
names a test directory.

## Termination

| Rule | When | Outcome |
| --- | --- | --- |
| verdict reached | the verdict agent returns a contract-valid verdict | complete |
| location unresolved | the reported file cannot be resolved inside the source snapshot, or is not a file | complete, `inconclusive` (`needs_info`); missing source is not evidence of safety |
| probe unrepairable | probe repairs (`HARNESS_MAX_PROBE_REPAIRS`, default 3) are exhausted and the last diagnosis is `probe_defect` | complete, `inconclusive` |
| environment unrepaired at probe time | the one probe-time environment repair (`HARNESS_MAX_ENVIRONMENT_REPAIRS`) did not help; it has its own counter and does not consume probe repairs | complete, decided on the evidence so far |
| negative not supported | `likely_not_exploitable` without a valid negative execution that reached the sink and a parsed, passing adapter control record (missing or unparseable controls fail closed, including offline and no-sandbox runs) | complete, `inconclusive` |
| environment unbuildable | the build and its repairs fail, including the partial-build fallback | complete, `inconclusive` |
| budget exhausted | a member exceeds its declared run budget | stop, `inconclusive` |
| contract unsatisfiable | the verdict agent cannot satisfy the evidence contract within its retries | stop, `inconclusive` |

A context agent's claim that the sink is unreachable does not end a run: it is a model assertion
even when its citations resolve, so the probe experiment still runs. No path name (a test or
vendored directory) turns into a safety verdict either.

`inconclusive` is a success state, not a failure: it is how the absence of evidence is reported
rather than being rounded to "not exploitable". It is also the escalation state.

**Conflict.** The deterministic verdict contract is the arbiter. Where a model's conclusion and
the recorded facts disagree, the facts win and the verdict is rejected; the system never
resolves a conflict by preferring the more confident agent.

## Limits

Per-member ceilings are the `metadata.budgets` in each spec, enforced through `UsageLimits` in
both the local and durable paths. A finding makes at most 26 agent runs (the sum of the max
calls above), with no parallel agents and one pass per finding; repairs are bounded per
interaction rather than by rounds. The system's own ceiling is the sum of its members'.
