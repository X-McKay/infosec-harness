# Credential broker timeout rationale

The historical evidence supports raising the provider wall ceiling from 90 to 240 seconds.
Two retained, successfully completed SDK model-request activities took 102.399756 and
104.230882 seconds. A 90-second ceiling excludes those observed successful executions.
This is a bounded timeout correction, not proof that earlier unknown requests would finish
within the new ceiling or that native qualification now passes.

The analysis was entirely offline. It read retained Temporal histories, case reports and the
sealed dedicated PostgreSQL dump; it did not contact the provider or open a database connection.
The private statistics artifact is `historical-timeout-rationale-stats.json`, SHA-256
`6cf0a070b3115b0c5b3629e7211da0eb30cf22b8cf98e2c764f1311d474a8f0a`.
It records the SHA-256 of every input used.

| Measurement | Observations | Maximum | Observed p95 |
| --- | ---: | ---: | ---: |
| Successful SDK model-request activities in the passed direct production graph | 20 | 102.400 s | 19.834 s |
| Successful SDK model-request activities in the earlier failed direct graph | 32 | 104.231 s | 22.247 s |
| Native completed request admission-to-commit wall | 80 | 44.032 s | 18.310 s |

The first two rows measure activity-start to activity-completion time. They include SDK
adaptation and response decoding, and exclude the activity's initial queue wait. They are
proxies for successful model-request execution, not provider-only timers. The earlier graph
failed its graph outcome, but its 32 completed model-request activities remain valid successful
execution timing observations. The native row includes preparation, claim and completion
work, so it must not be treated as a provider-only latency distribution. These cohorts are not
pooled into a provider latency estimate.

The p95 values use empirical nearest rank, `ceil(0.95 * n)`, among recorded successes only.
Both direct cohorts contain one successful execution longer than 90 seconds. Their low p95
values therefore do not justify ignoring the observed tail. The sample is small and selected;
none of these figures establishes a population percentile or latency SLO.

The eleven direct pilot cases made 37 requests and consumed 180.052 seconds in summed case
wall time; individual case walls ranged from 6.978 to 41.349 seconds. The passed production
graph wall was 232.589 seconds; the earlier failed graph wall was 295.471 seconds. Case and
graph walls include multiple requests, tools, sandbox work and orchestration, so they do not
measure an individual provider request. The latest diagnostic recon and partial-build cases
took 22.284 and 32.014 seconds for three and five requests respectively; their qualification
status remains `not_checked`.

The retained dump contains 15 `completion_unknown` records and 80 completed records. The
unknown admission-to-decision walls range from 1.377 to 92.648 seconds: four are at least
90 seconds and eleven are below 60 seconds. These are censored or interrupted outcomes, not
completed generation durations. No eventual completion time or uncensored percentile is
inferred from them, and the absence of a later result does not identify their historical cause.
The sealed dump, all unknown broker-owned uncertain holds and 119 deleted lease records were
preserved unchanged during this analysis.

The selected provider ceiling is `ceil((2 * 104.230882 + 30) / 30) * 30 = 240` seconds.
The factor of two and additional 30 seconds are explicit engineering buffers for observed
variation and the small sample; they are not a statistical confidence bound. This is below
the 300-second maximum considered and preserves a 90-second margin inside the existing
600-second model activity ceiling.

| Nested wall ceiling | Seconds | Construction |
| --- | ---: | --- |
| Preparation | 90 | Unchanged |
| Ledger hop | 30 | Unchanged; claim and completion each have an allowance |
| Provider | 240 | Historical maximum plus explicit buffer |
| Executor | 300 | 30 + 240 + 30 |
| Controller | 435 | 90 + 300 + 45 reconciliation |
| HTTP server | 495 | 435 + 45 reconciliation + 15 transport allowance |
| Worker | 510 | 495 + 15 acknowledgement allowance |
| Model activity | 600 | Unchanged; 90 seconds remain beyond the worker ceiling |

Every effective wait remains clamped to the remaining binding/root deadline. A larger wall
ceiling does not authorize an expired request, release an unknown hold, reclaim a dispatch
fence or resend an old request. Endpoint, model, retries, prompts, scorers, quality expectations,
request/token/resource caps and the existing activity ceiling remain unchanged. The timing
constants affect observable execution behavior and must be captured in the new executor image
and qualification provenance before fresh trials; prior manifests and results remain retained.

Longer waits retain capacity for longer and can increase cancellation/cleanup latency within
these bounded ceilings. They do not remedy input-admission limits or output-format failures.
Output shaping is addressed separately by the opt-in strict closed output-tool contract
described in the broker specification. Existing durable results remain readable, and unknown
requests remain fenced across replay/recovery. Controlled timeout regressions validate the
implementation; fresh finite native trials remain required for live qualification. This offline
timing analysis does not supply that execution evidence.

## Implementation checks

The 0.2.7 candidate passed `just check`, `just generated-check`, and
`just dev-skills-check`. The full deterministic suite passed: 2,451 tests, with 40 skipped
and 861 warnings. The warnings report unavailable pricing for stub models; the skipped tests
do not constitute live runtime evidence. Controlled SDK/HTTP transport regressions demonstrate
one dispatch under each ceiling: a scaled 150-second response is interrupted at the old
90-second ceiling and completes within the new 240-second ceiling. Binding expiry, cancellation,
trickling responses, immutable-contract matching and uncertain-hold recovery remain covered.

Eighteen strict-output regressions cover closed schemas, required nullable fields, local
validation/repair, unmodified environment maps and function tools, direct/executor/admission
wire parity, schema bounds and default-off identity compatibility. The finite qualification
runner now accepts a separately frozen review version 3 that declares this sole output-shaping
difference and retains the existing 15 unknown and 80 completed requests. It does not relax
model settings, quality checks, input caps or trial limits. Live native qualification and
provider grammar enforcement remain `not_checked` for this candidate until fresh trials.
UI validation is `not_applicable`: no frontend behavior changed. Hosted Temporal/database and
production Kubernetes deployment remain `not_checked`.

CI also exposed a scheduling race in an existing evaluator deadline test: its global
100-millisecond limit caused an ordinary stub case to time out in addition to the deliberately
slow first invocation. The test now reschedules the real evaluator deadline after that first
invocation enters, observes its cancellation, and verifies that every remaining invocation
answers under its normal budget. Exact failure counts remain unchanged. All 12 tests in the
file and five fresh-process repetitions of the three-case recovery subset passed. No runtime
deadline or expected outcome was changed by this test correction.

## Fresh native LocalOps qualification

The frozen v3 pilot at runtime source `2a42c6732d84f7b2a11b728a750066d48ce9b130`
passed all 11 native LocalOps cases, including execution, unchanged semantic scoring and
cleanup. It saved 40 new responses with no new uncertain completion or allocation overrun.
All authored budgets and effective model settings matched the original direct baseline.
The exact executor image was `sha256:472ea0188d1bf31cc77bc4f6e79fbc470a30f9a02af2bc1bd1fa6a322df3c045`.

Offline rendering of the saved requests with the pinned SDK confirmed strict closed output
schemas; environment planner, build repair and partial build retained their open environment
mappings. Raw output-tool arguments and typed outputs contained all required nullable fields.
This is reproducible request rendering and observed valid outputs, not a captured network trace
or proof of server grammar enforcement. The read-only analysis SHA-256 is
`7afff9f992cfa585e3cb69dcce09a81ed1ff40686ad59f2e448ab5a6e2a82e82`.

Temporal stopped before workflow submission or inference: the qualification fixture compared
global registration budgets with case-specific baseline budgets. Production Temporal already
resolves `config.for_source_files(deps.source_files)` for each invocation. The fixture correction
uses that same resolution for preflight and recorded evidence, preserving the full budget
comparison. Its regression rejects unscoped configuration and a source count that changes
effective limits. The consumed Temporal phase is retained; a fresh, bounded Temporal-only trial
is required. The withheld graph was retired through its exclusive execution guard.

Terminal verification found 135 records: the original 15 uncertain held requests and
120 completed requests. All 95 prior request/result records and the original uncertain
holds matched the independently retained dump; no accepted or dispatch-intent rows remained.
All 141 leases were deleted, native inventory was empty, and both providers and primary service
identities were unchanged. A fresh private database dump is sealed. Terminal evidence SHA-256:
`a4d13cd80836739e1862458d6383b6c246d01361f80ae33d58bcb0277902c049`.
The all-agent LocalOps gate is `passed`; the v3 Temporal gate is `failed` at fixture preflight;
its native production graph remains `not_checked`.

An auxiliary SQL analysis initially counted JSON `null` overrun values as non-null Python
objects. Its original sealed bytes are retained; the corrected analysis is a separate immutable
version with SHA-256 `7afff9f992cfa585e3cb69dcce09a81ed1ff40686ad59f2e448ab5a6e2a82e82`.
A separate correction record identifies the superseded counts. All files match the unchanged
terminal seal, and no authoritative report, ledger row, hold or database dump was changed.

The fixture correction and fresh Temporal-only scope passed all canonical checks and the full
deterministic suite: 2,484 passed, 40 skipped, 861 warnings. Independent review passed 138
provider/graph regressions; 167 focused fixture/runner checks passed. The exact registered
Temporal workflow name is now checked during owned-submission recovery, with a regression
that rejects its Python class-name alias. These changes affect qualification evidence and
recovery checks; the production executor and controller sources remain unchanged.


## Fresh native Temporal qualification

The frozen v4 Temporal-only trial at source
`ae9de1fc8364a955f67be0ba40d6044042de2781` completed all 11 cases. Ten passed execution
and unchanged semantic scoring; all 11 passed scoped cleanup and Temporal history replay,
and worker cleanup passed. Its 36 new broker responses completed without uncertain completion
or allocation overrun. Full per-case budgets and effective model settings matched the direct
baseline; the declared strict-output capability matched every executor contract.
The prior successful LocalOps phase was retained rather than repeated.

Intake failed after receiving a completed response with `finish_reason=length`: its entire
16,000-token per-response allowance was consumed by reasoning, with no output-tool answer.
This was not a provider timeout, missing output field, JSON formatting error or cumulative
invocation output-budget exhaustion. PydanticAI correctly rejected the incomplete response.
The ledger retained that completed response; it was not resent. The 240-second ceiling allowed
this response to return, but cannot make the model finish its answer within the token cap.

For the ten cases that produced typed outputs, saved arguments and typed outputs contained
all provider-required nullable fields. Pinned SDK rendering confirmed strict closed output
schemas and preserved open environment maps. Rendering is not a captured network trace or
server grammar-enforcement attestation. The exclusive terminal read-only analysis SHA-256 is
`94e72a3350a671c0a51f296412ec9677038eb7ec8f60b8747556e64b5299a69a`.

The native Temporal all-agent gate is `failed`; the production graph remains `not_checked`
because its prerequisite gate failed. Increasing the response cap or changing model settings
within this frozen trial would invalidate the comparison. A separately declared experiment
could test Qwen's documented non-thinking request option,
`chat_template_kwargs.enable_thinking=false`, after confirming support in the deployed serving
stack. The published API option is a candidate remedy, not evidence that this endpoint supports
it or that it passes qualification. See the [official Qwen model guidance](https://huggingface.co/Qwen/Qwen3.6-35B-A3B#instruct-or-non-thinking-mode).


Terminal preservation is `passed`: 171 ledger records comprise 156 completed responses and
15 original uncertain held requests, with no accepted or dispatch-intent records. All prior
135 request/result contents and all 15 uncertain holds matched the independent v3 dump.
All 152 leases were deleted, native inventory was empty, and scoped ledger providers were
absent. The two global provider identities, ten primary service identities, production image,
source and configuration remained unchanged. Dedicated infrastructure remains running.
A fresh private 0600 database dump is sealed; the withheld graph was strictly retired through
its exclusive execution guard without inference. Terminal evidence seal SHA-256:
`0d555c8a05c04018d6023943a179a640f3470d9dbb5e45fcd5ef72f3336802ab`.
The empty fixed-category diagnostic capture does not establish a historical failure cause.


Later per-agent non-thinking and targeted source-range repair experiments are recorded in
[CREDENTIAL_BROKER_THINKING.md](CREDENTIAL_BROKER_THINKING.md). The latest frozen intake
case passed through OpenShell with unchanged limits and scoring; fresh full native
qualification remains outstanding.


## V9 startup-control qualification candidate

The full v9 trial retained a pre-inference OpenShell supervisor failure: its Ready condition reported a 30-second idempotent boundary-control timeout, with no model request admitted. This is a censored startup failure, not a successful startup-duration observation or a provider latency estimate. The fixed message is shared by confirmation and agent launch, so it does not identify which exchange stalled or establish that more time will resolve a stall.

The next finite candidate doubles only the startup `Confirm` and `StartAgent` control ceiling from 30 to 60 seconds and records the fixed control kind on timeout. Initial attach and policy discovery remain at 300 seconds; ordinary control and connection-recovery waits remain at 30 seconds. The existing idempotent loop reuses its one request envelope; no new whole-call retry or model resend is added. The factor of two is an explicit engineering buffer for qualification, not a measured successful latency or production SLO. The ordinary controller preparation ceiling increases from 90 to 120 seconds. This total wall still may expire if both startup exchanges consume their maximum plus other setup work; cancellation must reap the owned CLI process and retain uncertain native mutation intent.

| Current candidate nested wall | Seconds |
| --- | ---: |
| Native startup Confirm / StartAgent | 60 each |
| Controller preparation | 120 total |
| Ledger hop | 30 |
| Provider | 240 |
| Executor | 300 |
| Controller | 465 |
| HTTP server | 525 |
| Worker | 540 |
| Model activity | 600, unchanged |

The 60 seconds after the worker ceiling reserve the independently retained 45-second reconciliation allowance and a 15-second acknowledgement margin. Binding and root deadlines still clamp every request wait; the unchanged 600-second case/activity ceiling can terminate a slower candidate. This deliberately reduces the prior extra outer margin, without relaxing admission, uncertainty fencing, sandbox enforcement or the actual activity deadline. Capacity can be occupied longer; qualification must measure cancellation and cleanup, not infer them from configured numbers.

Because the bundled timing source changes, the executor requires a fresh immutable image and contract even though its provider ceiling remains 240 seconds. The supervisor patch likewise requires a new image identity and actual readiness evidence. Fresh paused/scaled control regressions and a bounded zero-model startup soak must pass before another full original-case trial. This candidate is not yet a proven fix for the observed supervisor failure; old reports, unknown holds and native provisioning failures remain retained.
