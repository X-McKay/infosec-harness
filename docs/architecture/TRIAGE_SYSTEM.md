# Runtime architecture and boundaries

One Temporal workflow owns one investigation. PydanticAI's native Temporal integration
records model and tool activity results and resumes the agent loop after worker loss.
The investigator uses read/search/write/execute/run_probe tools and dynamically loaded skills;
there is no hard-coded sequence of reconnaissance, planner, builder and verdict agents.

Paths below are relative to `src/infosec_harness/`. `workflows/snapshot.py` captures
approved source without executing its hooks. `agents/investigator.py` defines the
investigator over the narrow toolbox in `tools/` (`workspace.py` for confined
read/search/write, `execute.py` for execute and run_probe); `agents/evidence.py` parses probe
observations and `agents/inference.py` carries model requests into the model sandbox.
`agents/` holds exactly one investigator; the directory introduces no parallel orchestration.
`workflows/investigation.py` prepares the workspace, runs the agent, validates its verdict
against receipts and citations, and cleans up; the agent's output validator gets citation
feedback from a read-only `check_citations` activity on the trusted worker (workflow code
never reads the snapshot), gated by the `citation-feedback` patch marker so histories
recorded before it replay unchanged; `workflows/worker.py` builds the trusted worker
and its identity guard. `contracts.py` contains strict inputs and results. `api.py` projects
Temporal state, including a bounded label-only view of run history, and serves operator report
files from `reports_dir` read-only; it does not maintain a second job ledger. `evals/` holds corpus evaluation,
replay, native qualification and `release-policy.yaml`.

OpenShell owns three native profiles:

| Profile | Code and permissions |
| --- | --- |
| workspace | Untrusted repository and generated experiments; narrowly allowed package egress; no model provider |
| probe | Fresh copy of the prepared workspace; no external network or provider |
| model | Only the small model executor and dependencies; explicit provider; no repository execution |

The trusted worker controls profiles. Model instructions cannot change policy, credentials,
images or limits. Provider credentials remain inside the native model boundary. The model
executor accepts serialized PydanticAI requests, makes one provider attempt and returns a
bounded response. There is no application credential-broker protocol or model catalogue.
Each model request is bounded by the same command budget as a tool command, capped at the
runtime's `max_timeout_seconds`: the executor receives that budget less 10 s as one
whole-request provider timeout, including connect, and an in-sandbox kill enforces it. An
executor that exits without a complete response raises a terminal `ModelExecutorError`; the
request's provider outcome is unknown and it is never resent.

`sandbox/openshell.py` validates native policy and provider admission, pins images and
verifies actual workload properties; `sandbox/execution.py` owns exec receipts and replay
fences, `sandbox/transfer.py` bounded uploads and snapshot capture, and `sandbox/executor.py`
is the only package module shipped into the model image. OpenShell v0.1.2's API does not
expose all outer isolation properties, so a dedicated-daemon Docker inspector reads the exact
native-owned containers.
It cannot serve as an execution fallback. The checks include namespaces, mounts, non-root
identity, capability removal, seccomp, no-new-privileges, network and cgroup limits.
Confinement is audited once per sandbox lifecycle. Reuse compares the native identity and
configuration without `metadata.resource_version`, which routine status writes advance, and
an order-canonical digest of the outer fence (Docker returns mounts in varying order); a
mismatch names the changed paths and closes owned work.

Each boundary check is a named entry in a table, not an inline condition: the confinement
proof's facts (uid, no-new-privileges, seccomp, capabilities, the `/dev/null` device numbers,
the Landlock, network, socket and credential discriminators, CPU and memory against the
profile), the outer-fence properties, policy admission and transfer bounds. A refusal names
the checks that failed, never the observed values or workload output, and a missing fact
fails its check.

Failures are typed so callers classify them without parsing messages:

| Type | Meaning |
| --- | --- |
| `OpenShellError` | A boundary could not be established or observed; the base of the adapter's errors |
| `ExecutionUnknown` | Dispatch may have happened; the operation is never automatically resent |
| `SourceRejected` | A trusted source tree was refused for transfer (unsafe file types or over a bound) |
| `SourceChanged` | The workspace no longer holds the original source bytes; raised before a probe runs and returned to the agent as integrity feedback naming the file |
| `UnsafeSnapshotMetadata` | A captured archive failed metadata admission |
| `ModelExecutorError` | The model executor exited without a usable response under a complete receipt |
| `WorkerIdentityMismatch` | A non-retryable activity refusal before any side effect: the worker is not the expected identity |

Command delivery is an external effect. A durable local receipt fence is fsynced before
sending it. Completed results can be reused; an interrupted dispatch with no terminal
receipt is unknown and is never blindly resent. The receipt directory and source snapshots
must survive worker restart and be available to any worker servicing this queue. Use a
single worker or shared durable storage with atomic exclusive-create semantics. Losing
this storage is not a recoverable replay guarantee.

The pinned gateway reports its own command timeout as exit 124 without native terminal
finalization, so an explicit exit 124 stays unknown. Commands therefore run under an
in-sandbox `timeout -s KILL` that fires 10 s before the command budget: a slow command becomes
a complete receipt with exit 137, and the investigator sees `timeout_feedback`. Shell commands
write their output to files inside the sandbox, which the wrapper prints after the command
ends, so a background or `setsid` child that outlives the kill cannot hold the exec stream
open. The wrapper prints at most 200,000 bytes of stdout and 60,000 of stderr and reports a
cut with one fixed marker line on stderr; both the tool return and finalization turn that
marker into `output_truncated`, so a cut probe never supports a definitive verdict. Native
output beyond the runtime's `max_output_bytes` is unknown execution, not truncation. The
gateway also decodes at most 1 MiB per gRPC message, so archives are delivered in parts of at
most 900,000 bytes; each part is its own replayable receipt, and the final extraction consumes
the staged parts. The read-only container inspector runs through the same bounded process
runner as source checkout: a slow, oversized, failed or undecodable observation fails closed.

Each probe runs in a separate offline sandbox. Before copying and after running it, the
runtime checks the original source against the captured snapshot. A definitive result
requires valid source citations, cited successful probe receipts, untruncated output,
source verification and explicit target, positive-control and negative-control observations.
The observations are self-reported by the authored experiment. They do not prove semantic
correctness, and a post-execution check cannot detect modification followed by restoration.
These limits require adversarial live evaluation rather than stronger claims from metadata.

Any contrary complete, source-verified probe blocks a definitive verdict, with one exception.
The verdict may list a contrary probe in `superseded_evidence_ids` when it ran at an earlier
agent step than the newest cited probe, and the summary must explain its flaw. A probe that
ran after the newest cited one can never be superseded. Finalization re-derives this rule
from receipts, keeps superseded excerpts within the ten-receipt report bound and adds a
limitation naming them.
If the agent has changed an original source file, `run_probe` refuses before copying: it
returns integrity feedback naming the file, with no exit code and no probe execution, so the
investigator can restore the file and run a new probe. Refused probes can never be cited.

Budgets bound model requests, tokens, tool calls, individual commands, transfers, outputs
and total workflow time. Cancellation reaches owned activities and cleanup. Tests exercise
real local Temporal replay, worker restart, deadline and unknown-delivery behavior, separately
from mocked OpenShell checks and actual native qualification.

Workflow generation v11 uses `investigate-v11` and binds every native model/tool activity
to the identity captured during preparation. Pure PydanticAI output validation gives
bounded feedback about exact receipt IDs and complete offline-probe claims before
finalization independently reconstructs trusted evidence. Output correction schedules
new deliberation within existing budgets; it never retries native dispatch. It breaks
compatibility with v10 and the
former staged graph. Drain old task queues before changing workers. The API lists this
generation's investigations only.

The pinned native Docker driver leaves the workload root filesystem writable. Filesystem
confinement is therefore OpenShell's mandatory Landlock policy, verified with both an
allowed workspace write and denied direct/symlink writes into world-writable `/dev/shm`.
An `/etc` denial alone would only demonstrate ordinary UNIX permissions and is insufficient.
The adapter records the observed rootfs property; it never substitutes a configured policy
name for these checks. Supervisor/driver/kernel changes require fresh qualification.

Evaluation binds the expected worker to its runtime code, packaged skills, release policy,
SDK dependency versions, model configuration and actual policy-file bytes. Admission
rejects a different worker before source capture or model dispatch; finalization rejects
drift. This identifies the configured model endpoint, not the weights served behind it.
Model history is bounded before native Temporal scheduling, and model responses are bounded
before activity completion. Server and local evaluation deadlines include cleanup time.

`harness eval` runs the frozen corpus once; each case gets a fresh workflow ID and is never
re-run. `--owned-worker` (used by `./dev eval`) runs the worker in-process on a fresh
`investigate-v11-eval-<hex>` queue recorded in the report and keeps it up until every owned
workflow and its cleanup is terminal. Failed workflows carry the outermost meaningful failure
type and a typed cause chain, which the report records. With `--keep-going` the cohort
continues only past a terminal failure classified from the raw, untruncated exception chain:
the outermost cause must be agent-level (`UsageLimitExceeded`, `UnexpectedModelBehavior`,
`ModelExecutorError`, or `InvalidCitation`: finalization refusing a model citation that
names no line range of the original snapshot; a generic `ValueError` is not), every further link must be on an allowlist (those types, `ModelRetry`
and Temporal's wrappers), and the chain text must name no cleanup, `ExecutionUnknown` or
`OpenShellError`. Any other type, such as a timeout, RPC error or `WorkerIdentityMismatch`,
stops the cohort. `--case` selects a diagnostic subset whose gates stay `not_checked`.

`--parallel N` (1 to 8, default 1) runs up to N cases at once against the one owned worker,
starting them in manifest order and keeping report rows in that order. A stopping failure sets
a latch before its case releases its slot: in-flight cases finish and no new case starts. A
parallel run records a limitation, since latency and executor failure rates are not comparable
to a sequential baseline and peak in-flight native operations rise with concurrency; the
capacity preflight (`native_occupancy_command`) bounds the cohort's total admissions, not its
concurrency. `harness replay` re-executes a recorded history against current workflow code
with model requests and native dispatch disabled; its report starts `not_checked`. Native
qualification likewise lists each check per profile (`boundary`, `roundtrip`,
`saved_operation`, `sandbox_reuse`, `cleanup`) as `not_checked` until it runs, with provenance
and a bounded error for a failure.

The server execution timeout of an investigation is its deadline plus `CLEANUP_RESERVE`
(`workflows/investigation.py`): the time owned cleanup can need after the deadline fires, a
waited `prepare` (10 min) plus three cleanup attempts (5 min each) with their retry backoff
and a 5 min margin, about 30 minutes. When a cohort with an owned worker cancels a case, it
waits up to the same reserve for that workflow to end. A server-ended run never executes its `finally`, so a timed-out or terminated case is
recorded with `cleanup: unconfirmed` and the next step for the operator.

Logs are one stderr handler at `Settings.log_level`, installed by `harness worker`, `api` and
`eval`. Records are `event=<name> key=value` lines carrying run, sandbox and operation ids,
error types and statuses, never commands, workload output, model text or credentials.
Workflow and activity code logs through `workflow.logger` and `activity.logger`, so replay does
not repeat workflow records.

The investigator loads every packaged skill under `skills/` as a deferred capability: each
model request carries one `- name: description` catalog line per skill, and a body is loaded on
demand. `skills/README.md` is that catalog, generated by `scripts/skill_catalog.py`;
`tests/agents/test_skill_catalog.py` bounds skill size, description length and the total
catalog the model sees. Skills hold expertise only and grant no permission.

The evaluation corpus is de-labelled: the investigator receives only a finding (title,
description, file path, CWE) and a repository snapshot whose variant directories are named
`a` and `b`, with no verdict words or explanatory comments and (with one documented
exception) no tests in the fixture, and both findings of a pair share one description. Which variant is exploitable is recorded only in
`eval-corpus/manifest.json` and the maintainers' answer key in `eval-corpus/README.md`;
fixture tests live outside every snapshot under `eval-corpus/verification/`.
`tests/evals/test_corpus_hygiene.py` enforces these rules.

Investigations stop before scheduling another model or tool activity once native Temporal
history reaches 32MiB. All tool calls, including deferred skill loading, execute sequentially
so the next check observes completed history. This independent limit can stop a run before
its token/request/tool limits and reserves room for finalization and owned cleanup. Model
activity input is capped at 1,000,000 bytes and its response at 512,000 bytes.
