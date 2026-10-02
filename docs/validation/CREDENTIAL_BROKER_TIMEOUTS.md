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
