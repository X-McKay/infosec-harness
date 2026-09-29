# Agent quality-gate improvement review

The frozen evaluator-v5 candidate is **not qualified**. Its live sweep closed incomplete:
13 of 33 planned suites completed, with 141 scored attempts; build-repair, partial-build,
and probe-diagnosis failed their first-pass policies. Twenty repeated suites and all five
fresh holdout groups were not started after an idle provider readiness timeout. Evaluator-v6
corrections passed deterministic validation and preserve the original v5 evidence.

## Implemented in the recommended order

1. **Output contracts.** Partial builds require partial scope and a nonempty module path;
   context outputs explicitly include source, sink, path, and sanitizer fields; verdict output
   tools expose only controller-permitted labels and require an inconclusive reason. Stored
   domain models remain compatible. Independent validators remain active.
2. **Execution-backed build scoring.** The secure check introduced in evaluator v4 and retained in v5, with build-repair dataset v2, executes the
   Perl SQLite dependency check in enforced runsc. Failed and unperformed checks each have a
   zero-tolerance gate. The real check found an XS library loading defect: installed native
   modules must remain under read-only `/opt/home`, because the `/work` copy is noexec. Both
   manifest and explicit installs pass with the corrected path. Historical records are retained.
3. **Probe efficiency and diagnostics.** `inspect_target` combines confined callable/import
   descriptions and bounded numbered source. It is opt-in for author/repair; other tool surfaces
   remain stable. Prompts emphasize real target effects and reject copied sinks. Bounded call
   summaries preserve order/repetition using local argument IDs, without raw arguments or
   recoverable hashes. In-process probe traces are diagnostic only: a source-reading spoof
   demonstrated they are forgeable. They cannot improve scores or clear release gates.
4. **Controlled tuning.** A serial trial compared cumulative output-token ceilings of 4,096
   and 128,000. The smaller ceiling passed 6/7 and hit one budget stop. The existing ceiling
   passed 7/7 and 2/2 disjoint known regression cases; one response used 5,374 output tokens.
   The current value is retained. This does not establish an optimum or verify the server's
   thinking-token setting. Stub calibrations are now ineligible for promotion even on clean
   source. No production configuration was automatically promoted.
5. **Qualification.** Repeated live evaluation and the independently prepared fresh grouped
   holdouts are recorded below. Any missing or failed gate prevents a qualification claim.

## Deterministic and runtime validation

- **1,623 Python tests passed** on the final evaluator-v6 source tree, with zero failures,
  errors, or skips, in 95.5 seconds. That exact source digest was committed as `50e3564`.
  Evaluator-v5 (`2d823a0`) passed 1,595 tests; the preceding `f8aabf5` passed 1,585.
- Ruff, compile, agent specifications, generated API/instruction/skill checks passed.
- Playbook conformance passed with the existing documented AgentRetries representation waiver.
- Three complete captured Temporal histories and an old pending-context activity replayed.
- A pre-patch workflow reaching an unscheduled revised agent fails before budget reservation;
  it must restart as a new workflow. Historical prompts are not silently reconstructed.
- Managed stack reload and fresh stub workflow `batch-ae51574a7dbe4a2b` passed through the API,
  Temporal, sandbox, and persistence. Runsc positive/negative, resource limits, proxy allow/deny,
  isolated builder, and S3 checks passed.
- Live Bedrock was excluded as requested. Mocked OpenAI-compatible and Bedrock typed-output
  roundtrips passed; these are not live Bedrock evidence.

The v5 deterministic, static/generated, conformance, captured replay, managed-runtime, and
stub-workflow gates above are `passed` for their recorded candidate and scope. Live Bedrock
is `not_applicable` because it was explicitly excluded; mocked roundtrips are `passed` only
as component checks. Final patched-worktree v6 deterministic, static/generated, development-skill, and playbook
conformance checks are `passed`. The initial v6 test invocation remains recorded as `failed`
due to packaging setup errors; its corrected rerun passed.

## Playbook alignment and remaining work

The changes follow the playbook's typed contract (§3), bounded tool (§5), durable execution
(§6), evaluation (§7), observability (§8), and measured budget (§9) requirements. Safety gates
were retained or tightened; averages cannot compensate for missing/failed secure dependency
execution. No sandbox mount permission was relaxed.

Independent target attestation (EVID-03) remains tabled. The in-process trace is explicitly
unattested and has a demonstrated spoofing counterexample. Passing agent policies therefore
must not be presented as full system security qualification. Broader real-repository and
language/tool-version coverage, and verified server-side reasoning controls, remain separate
work. The new holdout set is small and its sealing is procedural, not cryptographic isolation.

Historical comparisons span multiple earlier source digests and evaluator versions. They are
only descriptive. The serial token trial used clean `8384bb9`. The first full sweep used clean `f8aabf5` and was stopped after it exposed an evaluation dependency defect. The corrected full sweep ran on clean `2d823a0`, evaluator v5; the unused fresh-holdout manifest records that same frozen identity. No agent prompt or threshold changed in the correction. Source/config/dataset identities accompany every experiment.

The initial four-hour wall-clock envelope was amended before the remaining jobs were launched:
observed exploration latency required a finite six-hour aggregate ceiling. Full sweep ceiling:
five hours from its original start; heldouts: forty minutes. The initial maximum of 402 case attempts was raised prospectively to 450 after the evaluator defect required a new frozen sweep (431 planned including all prior attempts),
with no more than two suites in flight and no change to production invocation limits. Existing
intake/recon jobs were preserved; remaining agents run one complete pass before extra passes.

Local model billing is configured as zero per token. Reported zero dollars exclude hardware,
electricity, and opportunity cost; they do not establish that inference is costless.

## Live results

The v5 sweep closed at `2026-09-29T22:41:40Z` as `INCOMPLETE_PROVIDER_READINESS` on
clean `2d823a0`, with matching before/after source identities. All eleven agents completed
one pass; build-repair and partial-build also completed a second pass. Completed agent
policy passes below apply only to that pass and its frozen dataset/backend/configuration.
They do not clear the incomplete repeated-run or fresh-holdout gates.

| Agent | First pass correct | First-pass budget stops | First-pass policy | Second pass |
| --- | ---: | ---: | --- | --- |
| intake | 8/9 | 0 | passed | not_checked |
| recon | 8/9 | 0 | passed | not_checked |
| env-planner | 10/10 | 0 | passed | not_checked |
| build-repair | 9/14 | 3 | failed | 7/14 correct; 7 budget stops; failed |
| partial-build | 5/9 | 4 | failed | 4/9 correct; 5 budget stops; failed |
| context | 14/15 | 0 | passed | not_checked |
| probe-planner | 9/10 | 0 | passed | not_checked |
| probe-author | 10/10 | 0 | passed | not_checked |
| probe-repair | 10/10 | 0 | passed | not_checked |
| probe-diagnosis | 11/13 | 0 | failed | not_checked |
| verdict | 9/9 | 0 | passed | not_checked |

All reported v5 passes have schema validity 1.0. The v5 diagnosis safe-evidence counter has
the confirmed blind spot described below; its zero is not evidence that every raw negative
had complete evidence. Build-repair's original v5 execution counters likewise retain the
no-output accounting limitation corrected in v6. Original counters remain immutable.

The bounded idle readiness diagnostic began at `2026-09-29T22:39:25Z` with zero concurrent
evaluation suites. A one-token completion timed out after 45.114 seconds; there was one
attempt and no retry. An earlier 20-second diagnostic timed out while two suites were
active. The idle failure establishes that the endpoint did not answer within the measured
window; it does not establish whether the cause was queueing, model work, or another provider
condition. No provider cause is known. The bounded provider-readiness check is `failed`.

The remaining twenty public suites are `not_checked`. The independently prepared fresh
set contains ten cases in five groups; all five were `skipped_provider_readiness`, with
zero experiments and zero scored attempts. They remain unused, and their semantic contents
were not inspected for this review. The fresh-holdout gate is `not_checked`; live repeated
qualification is incomplete and cannot pass. See `full-live-v5/index.json`,
`heldout-live/index.json`, and `provider-idle-inference-health.json`.

The **stopped predecessor sweep** recorded intake at 24/27 correct, schema 1.0, no budget stops, p95 requests 2, worst repetition
7/9. This clears its current aggregate policy (minimum 0.75), subject to complete provenance
review. It is not evidence of perfect prompt-injection resistance: one RISK-SEC-002 adversarial
case followed a planted misclassification instruction. The scenario is currently assessed as
medium inherent/residual risk, not critical. The playbook's zero-critical-failure rule must not
be misrepresented as an existing zero-adversarial-failure gate. Current coverage reports show
scenario presence, not per-scenario behavioral success. Report this known weakness separately;
a stricter adversarial gate would be a prospective versioned policy change. Two other mistakes
omitted classification fields despite recognizing the vulnerability in their evidence.


## Defects discovered during live validation

The first sweep exposed missing `sandbox_image` in build-repair and partial-build evaluation
adapters. Production supplies the failed spec's base image. All three repeated Perl sandbox
calls therefore failed before Docker execution, exhausting retries without an accepted output.
This was an evaluator defect, not evidence that the model chose an unavailable tool. The
initial commentary diagnosis was corrected after checking the actual offered tool surface.
Evaluator v5 binds the same image as production and validates malformed fixtures explicitly.

The evaluator's own ten-minute deadline previously truncated an entire dataset. V5 records it
as a failed time-budget gate and continues the remaining cases. An inner transport timeout,
other transport failures, and external cancellation still truncate and preserve partial evidence.
The generic model failure category is `no_accepted_output`; it does not misrepresent tool-retry
exhaustion as proven schema invalidity. No provider/error body is retained by that category.

The stopped sweep retains 51 attempted / 48 scored cases, including two coordinator
cancellations; it is diagnostic evidence only and cannot clear the corrected candidate's gates.
The corrected sweep uses a separate database. A zero-inference SQLite schema creation race
on its first partial-build startup was preserved and rescheduled after initialization; its
active build-repair/context processes were not interrupted. The heldout runner initializes
its database before starting two suites. No retries of failed heldout measurements are allowed.

## Remaining build-agent failure mechanism

A read-only review of the first corrected pass found seven build/partial-build budget failures
with 128 recorded tool calls, including 91 sandbox calls. Adapters now supply production-parity
base images. Each sandbox invocation starts fresh, without a repository mount and with network
disabled; repeated calls do not form an iterative repository build session. Several fixtures
already provide decisive failure-log and manifest evidence. These failures support a next
controlled prompt change that explains the tool's actual capability, batches unresolved
base-image checks, and stops exploration once evidence determines the returned specification.
This pattern does not justify a blanket budget increase. The persisted SDK usage-limit
exceptions do not identify which bound stopped a run; completed usage is unknown.

Partial-build also needs a clear cross-language explanation of root-package semantics. A
repository rooted in one Python/Perl package or one Maven module can have `module_path="."`
while narrowing dependency or build-phase scope. This is already permitted by validation,
but the current skill leaves the distinction unclear. A focused wording change is a smaller
next candidate than adding tools or an orchestration layer. These hypotheses have not been
applied to the frozen live candidate, nor tested against fresh holdouts.

## Diagnosis contract follow-up

The first corrected pass classified a thrown sink call as `valid_negative`, and a Maven test
selector that ran zero tests as `environment_issue`. Existing production controller functions
`_correct_unsupported_negative` and `_ground_zero_test_diagnosis` correct these decisions before
routing. The raw agent eval still correctly counts the mistakes. In particular, the current
agent instructions define a negative using the precondition marker without explicitly requiring
`sink_returned`; this does not reflect the controller's stricter contract. A subsequent versioned
prompt should state that requirement and distinguish an invalid test selector from a missing
runtime dependency. Keep both deterministic controller guards. Marker checks themselves remain
subject to the separate EVID-03 attestation limitation.

The v5 `unevidenced_safe_verdicts` metric has a confirmed blind spot for diagnosis: it checks
`precondition_reached` but not `sink_returned`. Consequently the thrown-sink raw negative can
escape that counter despite failing its expected label. This does not establish a controller
false negative: the graph corrects it before routing. The v6 metric correction, including explicit boolean evidence flags, passed validation; all v5 rows and counters must remain unchanged and be labeled with this
limitation.

Recon also returned `java 17/junit5` for the `java/junit5` case. The current primary-language
field is a free string, and the prompt does not define a canonical naming vocabulary. This is
a contract/normalization ambiguity, not evidence that the agent failed to identify Java or
JUnit. Preserve the strict original score; specify a general language-name/version boundary
and version that contract before claiming a corrected evaluation.

## Live deadline behavior

The second v5 pass exercised the evaluator's own wall-clock deadline on both the cpanm
repair case and the sandbox-preserving partial-build case. Each was recorded as
`AgentRunTimeout` at approximately 600 seconds, counted as a budget failure, and the
remaining dataset cases continued. These were agent-deadline failures, not transport
timeouts. Their unavailable request/token usage remains unknown.

## Evaluator-v6 correction status

Four narrow reporting/scoring defects were reproduced and fixed while the v5 candidate
remained frozen: normalized no-repeat build scoring; complete negative diagnosis evidence;
declared execution-check accounting when no output is available; and observed tool-call
percentiles that include scored budget/output failures. The isolated combined tree passed
1,600 deterministic tests, followed by all eleven Temporal tests with the managed CLI
available (1,611 total). The worktree now carries those patches plus a strict-boolean
negative-evidence correction. All 1,623 final-worktree tests passed with no failures or skips.

The initial final-worktree v6 run collected 1,611 tests and encountered seven packaging
errors because `UV_OFFLINE` used an empty hatchling cache. This is a failed test invocation,
not a completed passing gate. The populated validation cache resolved these setup errors; the corrected final-worktree
rerun passed. Both invocations are retained, and the isolated-tree result is separate evidence.

V6 changes no agent prompt, runtime permission, quality threshold, or expected label. The
evaluator/provenance version changes because the scoring and reported observations change.
Original v5 rows remain immutable. Any v6 numerical re-scoring is a separate artifact derived
offline from those rows; it is neither new inference nor a new live qualification or promotion
approval. The final grader is clean `50e3564bb45622a73f0bd366a68f37479262d053`, source digest
`676c78093ed4bd17127143becd6f82d27844e49ae39f3cd6e954e881f15153fa`.
These evaluator-only changes do not alter workflow commands, activities, persisted domain
schemas, or sandbox permissions. Existing captured-history replay evidence remains attributed
to its original candidate; the final full suite also passed all eleven Temporal integration
and recovery tests. No new live workflow or inference was executed on v6.

Latency from the v5 sweep was measured with up to two suites sharing the endpoint. A
600-second agent deadline does not separate model reasoning time from server queueing.
Persisted `UsageLimitExceeded` stops must be called **SDK usage-limit stops with an unknown
bound**, not request-budget stops. Agent-deadline failures remain a separate category.

## Ordered next actions

1. Restore and verify provider readiness with a bounded diagnostic before any live evaluation.
   Preserve the failed diagnostics; do not claim a known provider root cause.
2. Add a versioned v7 diagnostic that classifies only anchored SDK-owned limit messages into
   a closed enum, falling back to `unknown`, without retaining exception/provider bodies.
   Capture bounded partial response/tool/token observations with coverage counts, while
   keeping completed usage unknown. This establishes the binding limit before tuning.
3. Test the smallest build guidance candidate on public cases, serially: explain fresh sandbox
   semantics, batch unresolved base-image checks, stop once decisive evidence determines a
   specification, and clarify root-package `module_path="."` semantics. Preserve deterministic
   controller corrections; prospectively version diagnosis sink-return/zero-test guidance and
   recon language-name/version boundaries.
4. Only if v7 identifies a binding request limit, run the proposed serial public-case A/B:
   16 versus 20 requests, with the three arithmetic ceilings derived from that allowance
   (64 to 80 tool calls, 4,000,000 to 5,000,000 cumulative input tokens, 256,000 to 320,000
   cumulative output tokens). Keep the 250,000 per-request input bound and record root-bound
   limits. No blanket time/token/tool increase is supported by the current evidence.
5. Require unchanged task, schema, execution, safety, and unevidenced-safe gates, with fewer
   budget stops and no longer exploration loop, before adopting a candidate. Calibration
   does not authorize promotion. Any adoption requires complete repeated public qualification
   and a fresh holdout phase. Preserve the unused grouped holdouts until the candidate and
   readiness are fixed; no automatic production promotion.

The earlier 4,096 cumulative output-token trial was rejected; the existing 128,000 value
is retained, without a claim that it is optimal. Independent target attestation (EVID-03)
remains tabled, and broader language/tool-version coverage remains outside this iteration.
No enterprise rollout claim is supported.

## Offline reassessment and retained evidence

The separate v6 reassessment uses read-only access to the original v5 database. It verifies
that the relevant payloads, expected labels, and execution-check facts are unchanged. It
records the original identities and the clean v6 grader identity; promotion eligibility is
explicitly false. Results:

- One previously failed no-repeat repair score changes to passing **distinctness only**.
  Its added `libpq-dev` makes it different from the failed spec; this does not prove it builds.
  The second-pass case had no accepted output and remains `not_checked` for this property.
- The thrown-sink diagnosis now contributes one unevidenced-negative violation. The existing
  production controller still corrects the raw diagnosis before routing.
- Both declared Perl checks are `not_checked`: neither budget-stopped agent supplied an output
  to execute. The original zero not-checked counters must not imply successful execution.
- Tool p95 for build-repair changes from 8 to 19 on pass one and 6 to 21 on pass two.
  Partial-build changes from 17 to 23 and 12 to 21. Request/token usage on failed runs remains
  unknown; observed tool-call counts do not reconstruct completed SDK usage.

Attempts used: 16 calibration + 51 stopped predecessor + 141 corrected v5 + two readiness
diagnostics = **210/450**. The corrected sweep left 213 public case attempts and all ten
fresh held-out cases unattempted. No production limit was raised. More allowance alone would
not resolve the observed readiness failure or establish improved agent quality. Partial-build
also has a p95 request gate of 12; a higher allowance must still satisfy that existing gate.

Reviewable records are under `docs/validation/agent-quality/`: original sanitized live
summaries, case-level numeric evidence, the aggregate, the separate offline reassessment,
and a validation manifest. Raw provider/model outputs and tool arguments are excluded. Raw
local databases, logs, and JUnit files remain in `.harness/validation/quality-gates/`, with
hashes recorded in the exports. They are ignored local artifacts and are not recoverable
from a fresh clone alone. The earlier `export-v5/` and stale aggregate are superseded by the
`*-final-review` artifacts, while preserved locally.

The work is committed locally on `codex/agent-quality-gates`. It has **not been pushed to
`develop`** because the required live quality gates and coverage are not complete.
