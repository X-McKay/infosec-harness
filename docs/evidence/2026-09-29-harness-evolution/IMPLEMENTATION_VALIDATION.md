# Harness evolution implementation and validation

Implementation branch: `codex/harness-evolution`, based on develop `6dbb09e`.
Scope: foundations for the initial milestone in `HARNESS_EVOLUTION_SPEC.md` §15.0.
This file records completed implementation checks and remaining acceptance gaps, not a release approval.

## Delivered implementation under validation

- Revision-aware atomic source snapshots, explicit working snapshots, confined file access,
  citation byte digests, bounded source/search/process output, and conservative negative verdicts.
- Environment readiness enters bounded repair; repeated ineffective plans stop. Component
  discovery exposes experimental/unsupported compatibility rather than claiming universal support.
  Four typed ecosystem declarations cover all eight ENV-02 capabilities and record partial support.
  TypeScript shares the JavaScript profile; unknown languages remain explicitly unsupported.
- Effective provider settings and budget identities shared by eval and execution; both existing
  backend families retained; production-equivalent agent limits applied during component evals.
- Bounded, grouped calibration/holdout experiments, attempt-level observations, strict comparison
  checks, explicit missing-cost/usage semantics, and failed/truncated experiment preservation.
- Durable acceptance/start reconciliation, activity-backed per-finding persistence, preparation
  accounting once per repository group, independent child failure handling, cancellation intent,
  ordered idempotent progress records, evidence manifests, and append-only review history.
- A compare-and-swap root reservation ledger covers requests, tokens, cost, tool calls, agent
  runs and aggregate workload seconds, with an acceptance-time deadline and pinned agent
  configuration identities. Heartbeats deliver checkout/workload cancellation and wait for cleanup.
  It prevents concurrent allocation beyond configured ceilings. Interrupted or potentially retried provider work retains uncertain reservations.
- Findings, Workflows, Evaluations, Metrics, and Settings UI; neutral light/dark/system theme,
  shared shadcn-style components, active-run polling, honest errors/staleness/unknown values,
  evidence and review details, whole-population metrics, distributions, trends and stage breakdowns.
- Two canonical development skills and generated Codex/Claude copies; common checks; managed
  tool versions; isolated development project identities and editable application mounts.

## Validation evidence

These results are local development evidence, not release approval. Reports under `.harness/`
are ignored artifacts in this worktree. A sanitized, versioned aggregate summary is retained in
[`validation/harness-evolution-evidence.json`](harness-evolution-evidence.json).
Stub scores are deliberately not quality gates.

| Check | Status | Evidence |
| --- | --- | --- |
| Full deterministic suite | passed | 1,519 passed with no skips or failures after the live-review fixes, including nullable eval usage, bounded typed diagnostics, scorer aliases, partial-build contract enforcement, pending-batch contracts, artifact integrity, root configuration pinning, deadline cancellation, terminal-persistence recovery and independent model/execution usage completeness; `.harness/validation/pytest-final-governance.xml`. Wheel build errors now fail instead of silently skipping packaging checks. |
| Local Temporal | passed | Seven real-service tests cover acceptance before worker start, incremental output, component preparation, cancellation before/during work, root-budget exhaustion, and worker replacement; inference and sandbox activities are stubbed/mocked. Eight budget tests also cover older servers without root metadata and replay compatibility. `.harness/validation/temporal-final.log`. The reviewed full suite also exercises failure after successful finding-stage calls, mocked ADO writeback and cancellation during it, and terminal persistence succeeding after three database failures. No actual ADO comments were sent. |
| Backward replay | passed | Parent, preparation, and finding histories captured from unchanged `6dbb09e` replay against current workflows. `.harness/validation/histories/baseline-{0,1,2}.json`; replay passed again after the final workflow fixes in `.harness/validation/replay-final-review.log`. |
| All-agent eval machinery | passed | All 11 full datasets ran and persisted 118/118 cases; every command exited zero. `.harness/validation/final-stub/index.json` links each report and log. This is not 118 successful security judgments. |
| Budget calibration machinery | passed | Two 3-case candidates plus a grouped 2-case holdout completed. Effective configuration, attempts, distribution summaries and limits are recorded. `.harness/validation/final-stub/calibration.json`; dirty source correctly blocks promotion. |
| Eval source consistency | passed | Before/after captures, all 11 agent reports, and calibration share the digest recorded in `.harness/validation/final-stub/index.json`. Future source changes require a new identity for comparisons. |
| Provider contracts | passed | OpenAI-compatible and Bedrock transports exercised through mocked tool-call and typed-output round trips, including effective settings and budget identities. |
| Persistence/metrics | passed | SQLite migration/model parity and downgrade, competing root reservations, 205-finding aggregate fixture, missing usage, failed/cancelled rows, and idempotent progress. Real PostgreSQL schema parity and head/0003/base round trips also passed; duplicate progress, concurrent reservations, review history, cancellation and metrics were exercised in a disposable PostgreSQL database. `.harness/validation/postgresql.log`. |
| Packaging | passed | Installed-wheel validation is included in the full deterministic suite. |
| Frontend | passed | Two deterministic URL-state tests, typed endpoint response tests, TypeScript and production Vite build; desktop and 390px browser checks, light/dark themes, keyboard/zoom spot checks, real stub experiment reports, and explicitly synthetic Demo distributions. Histogram links match their exact filtered rows. Refactored evaluation views were verified again in-browser; nested latency observations render, subsecond values use milliseconds, and case percentiles match the backend nearest-rank method. The managed UI was also checked after restart: ready environment, actual exit-zero probe, seven agent invocations and durable event timeline rendered from the real Temporal result. |
| Generated artifacts | passed | Generated contracts now cover all UI endpoints; OpenAPI/client schema, canonical Codex/Claude skills and instruction drift checks. Ruff and compilation pass. Handwritten frontend formatting is pinned and checked in CI; generated types are excluded. |
| Playbook structure | passed | Agent, skill, risk and system checks pass with the existing documented `AGENT029` waiver and warnings; `.harness/validation/playbook-final-corrected.log`. CI and development skills pin reviewed playbook revision `9e7fc03f2e1253be3e2adea10663ddf429646cea`. Structural conformance does not prove behavioral adherence. |
| Managed macOS runtime | passed | On this Apple Silicon host, a fresh checkout-owned VZ VM ran the actual isolated build and probe through API/Temporal, persisted ready-environment evidence and nonempty root-budget operations, and passed S3 put/get/delete. Actual no-network and proxy allow/deny/private/direct checks passed; a fresh production builder verified runsc, sole internal network and exact proxy configuration. PID exhaustion and an OOM kill demonstrated enforcement; CPU quota was inspected. `.harness/validation/runtime-smoke.log`. Stop followed by warm `./dev` preserved the same validated batch and S3 sentinel; `.harness/validation/runtime-warm-start.log`. A fresh final-review batch (`batch-c074b3443c0199ca`) also passed pending polling, real sandbox execution, all six root budget dimensions, configuration pinning and manifest schema v2; `.harness/validation/runtime-final-fresh-batch.json`. The post-live telemetry correction passed on fresh batch `batch-67a49dd5e77291c8`: 1,465 reported tokens reconciled with six invocations, zero token cost and retained uncertain execution reservations; `.harness/validation/runtime-provider-resource-separation.json`. This is not clean-host OS acceptance. |
| Clean Linux onboarding | not_checked | QEMU/KVM bootstrap implemented; no clean Linux host execution has been performed. |
| Live OpenAI-compatible profile | failed | All 118 distinct cases across 11 full datasets executed across two recorded source phases after the endpoint recovered from `502 upstream_unreachable`. Partial-build, context, probe-author, probe-repair and verdict fail at least one acceptance gate. A separate final-source partial-build 1.0.1 run completed 6/9 and still fails task-success and schema-validity gates; invalid-output forensics produced valid typed outputs on three of four reruns, with one recurrent invalid output. The token-budget study terminated incomplete and did not qualify or promote a candidate; both build-repair diagnostic reruns completed with typed outputs and failed their coarse assertions. This is not a qualified model profile or a uniform-source release comparison. |
| Live Bedrock | not_applicable | Explicitly excluded from this validation by the user. Mocked contract coverage remains required and passed. |

The user explicitly approved sending the packaged evaluation prompts and repository fixtures to
`<self-hosted-endpoint>`. The original sweep preserved the same source digest before and after:
`fe7cdbe56792a41366dd1f854da2b753ce033b9b8211bcce319364d7c285f6ae`.
Its reports, SQLite records, logs and policy summary remain under `.harness/validation/live-approved/`.
Intake and early recon cases ran serially; the coordinator then allowed two suites concurrently.
Latency observations are descriptive, not a controlled serial benchmark. All model tiers resolve
to the same served Qwen model. The configured zero token price excludes hardware/compute costs.

| Original live suite | Recorded / planned | Correct | Acceptance observation |
| --- | --- | --- | --- |
| intake | 9 / 9 | 8 | Aggregate policy passes; the planted report instruction caused a real CWE misclassification. |
| recon | 9 / 9 | 7 raw; 9 rescored | Two unambiguous JUnit aliases were scorer defects. Original v2 report is preserved; `recon-rescored-v3.json` is a separate deterministic derivation, not new inference. |
| env-planner | 10 / 10 | 10 | Original policy passes. |
| build-repair | 14 / 14 | 12 | Aggregate policy passes; two reduced-label failures require typed-output diagnostics before attributing cause. |
| partial-build | 9 / 9 | 3 | Five outputs chose full scope despite the partial-build contract; one output failed validation. Task-success and schema gates fail. |
| context | 15 / 15 | 12 | Two invalid outputs and one unsupported `unknown` to `unreachable` judgment fail acceptance. Context assertions do not independently grant a negative security verdict. |
| probe-planner | 3 / 10 | 3 | Truncated by endpoint 502; not qualified. |
| probe-author | 0 / 10 | — | Truncated by endpoint 502; not checked. |
| probe-diagnosis | 0 / 13 | — | Truncated by endpoint 502; not checked. |
| probe-repair | 0 / 10 | — | Truncated by endpoint 502; not checked. |
| verdict | 0 / 9 | — | Truncated by endpoint 502; not checked. |

The recovered full suites used evaluator v3 and the stable source digest
`fb24546fba24e30f556bb01917b51b3667974a6e99b8b95021a7c7ccc663f2d3`.
They remain separate under `.harness/validation/live-reviewed/`. A simultaneous cold SQLite
bootstrap failed before the first planner call; the serial planner recovery completed against
the initialized database and preserved the failed coordinator artifacts and hashes.

| Recovered full suite | Correct / planned | Acceptance observation |
| --- | --- | --- |
| probe-planner | 10 / 10 | Policy passes. |
| probe-author | 9 / 10 | One adversarial convention caused the probe to reimplement the query instead of calling the target. The p95 model-request gate also fails at 14 requests. |
| probe-diagnosis | 13 / 13 | Policy passes. |
| probe-repair | 10 / 10 | Correctness passes, but the p95 model-request gate fails at 14 requests. |
| verdict | 8 / 9 | One invalid output fails the schema-validity gate. |

The subsequent review adds a partial-build-specific scope/module validator (agent version
1.0.1), generated response contracts for the remaining APIs, a pending-batch regression,
artifact integrity checks, and extended durable budgets. Accepted configuration digests are
checked before agent dispatch, and workflow construction no longer performs configuration I/O.
The source digest measured by the final live follow-ups is
`e38343c1a8188f98dd4cc44f51d4645013aa6ce467ebe0af5bd0ac4c5208fa0e`; the complete
118-case stub run and calibration machinery under `.harness/validation/final-stub/` share it.

The separate full-dataset partial-build 1.0.1 rerun on that measured source recorded 9/9 cases and
6 correct. Three invalid outputs leave task success and schema validity at 0.6667, below the
unchanged 0.85 and 1.0 gates; p95 model requests is 10 and passes its limit of 12. Usage was
observed for 6/9 attempts, so a complete-population token average remains unknown. Its timing
overlapped the forensic run and is descriptive. It does not replace the original fe7 result.

Four non-release forensic reruns used that measured source and original agent retry settings. Three
produced valid typed outputs; the `sqli-fixed` context case again exhausted output validation,
with bounded output-tool and validation feedback retained in the private failure artifact. These
new reruns cannot reconstruct or replace the original invalid outputs.

The review corrections use evaluator v3: bounded framework aliases, retained typed output,
and aggregate usage that remains unknown when any attempt lacks usage. The original v2 average
token/cache values are incomplete where usage is missing; use the attempt records and explicit
coverage instead. Historical reports have not been rewritten to claim the fixes were present.
The isolated 512/2048 thinking-token study completed on that stable measured source but the planned
study is incomplete. The 512 trial attempted seven cases, scored six and got four correct; two
outputs were invalid and the final timed-out attempt was retained, with usage observed for 4/7.
The 2048 trial completed 7/7 correctly and was selected for the held-out check. Both held-out
outputs were invalid (0/2), with unknown usage, so the candidate is not qualified. Across the
three experiments, usage was observed for 11/16 attempts. The command preserved its report and
exited zero, while the enclosing driver rejected the incomplete study. Promotion eligibility is
false and no default was changed. The server accepted the requested settings, but its undisclosed
version/parser configuration does not establish enforcement of the thinking-token field.

Both selected build-repair diagnostics completed with bounded typed output and failed their
existing coarse assertions. One explicitly invented a private registry. The Perl output relied
on `cpanm --installdeps .` rather than naming the missing driver and used inconsistent install
and library prefixes. The current fixture declares that driver as a test dependency, so the
literal driver-name score alone cannot establish whether installation would succeed; actual
build/probe execution is needed to resolve it. These new outputs cannot reconstruct the original
two reduced-label failures, and neither the original scores nor expectations were rewritten.

After the live calls finished, a persistence-only correction separated model usage completeness
from uncertain sandbox-execution reservations. It changes no agent prompt, configuration, eval
expectation or inference path. The final deterministic suite and fresh runtime workflow cover that correction; the earlier live
source identities remain unchanged and do not identify the final committed documentation/code.
A final governance-only correction also derives risk-assessment versions from agent specs, with
a cross-artifact regression for every agent; playbook conformance passes with the existing waiver.

## Remaining acceptance limits

- Actual build/probe, network/proxy denial, PID and memory enforcement have passed on the managed
  macOS runtime. CPU quota has been inspected rather than benchmarked. Manual forced removal
  is not production crash/cancellation cleanup evidence. Warm restart preserved the validated workflow and S3 data. Clean-host macOS/Linux
  onboarding remains unverified; the current host was not a clean OS installation.
- Local and Temporal execution now prepare separate environments for discovered components,
  including distinct Java release requirements. Description-only intake can rebind preparation
  when it resolves a nested location. This is not proof of the full ecosystem/tool-version
  matrix; compatibility remains experimental until actual runner fixtures pass.
- `unit-probe-execution/v1` separates controller-owned process observations from legacy
  self-reported markers. Runner discovered/executed counts remain unavailable for that adapter,
  and marker nonces do not authenticate target binding or exploitability. Positive verdicts
  still use that legacy oracle path plus diagnosis; they must not be advertised as independently
  authenticated exploit evidence. The strong EVID-03 release gate remains incomplete.
- Provider transport/activity retries can consume usage the SDK never returns. Root accounting
  retains that uncertain exposure rather than declaring a falsely exact total. Known-zero
  pricing can establish zero cost while token usage remains unknown. Root ceilings are
  provisional deployment bounds, not defaults selected by these stub measurements.
- Durable ADO writeback preserves the existing payload-hash retry behavior. A process loss after
  Azure DevOps accepts a comment but before the local sync row commits can still duplicate that
  external effect; exactly-once writeback requires a remote idempotency/reconciliation protocol.
- Worker replacement and explicit cancellation are covered. Terminal persistence retries transient
  failures durably with capped backoff. Explicit server-side workflow termination can still bypass
  workflow-owned cleanup; exhaustive process-loss reconciliation and every historical branch are
  not covered by these scenarios.
- Automatic prepared-image eviction is disabled: age alone cannot establish that a workflow
  has finished using an image between activities. Manual cleanup no longer force-removes images
  and requires quiesced assessments. Durable image leases and bounded automatic retention remain
  incomplete; images can accumulate. This preserves active resources without claiming SNAP-04's
  full cache-lifecycle implementation.
- Persisted operational evidence manifests identify the persistence worker's packaged harness
  source, graph/workflow code and verdict policy, and retain the final available build/smoke
  outcome and build-log reference. This scope does not assert that the same worker ran earlier steps.
  They do not pin mutable registries or dependency services, or prove that one worker build served
  every step of a resumed workflow, so exact byte-for-byte reproduction is not claimed.
- Content-addressed artifact reads verify their digest and distinguish missing from corrupt data.
  The initial local policy retains objects indefinitely until explicit whole-object deletion;
  there is no automatic retention scheduler or reference counting. Because an object can be
  shared, deletion is an administrative action that must first retire every referencing run.
- Root limits apply to durable batch execution. Execution-resource accounting reserves aggregate
  workload seconds at the configured per-container CPU/memory ceilings; it is not measured GPU
  or CPU consumption. Completed activities can retain their full retry envelopes when prior
  attempts cannot be observed, so a later operation may be refused conservatively. Old ledgers
  retain their original dimensions. Deadlines stop assessment dispatch and request cancellation;
  cleanup and durable terminal writes may finish later, and provider billing cannot be forcibly
  stopped or measured exactly by the controller.
- Comparable release gates require clean, identical source provenance. Comparisons across
  intentional source changes are currently descriptive and cannot establish promotion.
- Browser spot checks are not a screen-reader/accessibility audit or a clean-host usability study.
  Skill structure and generation checks are not a comprehensive activation/adherence study.
- Prompt and binary content are excluded from default model telemetry. Evidence records still
  intentionally contain assessment output and require deployment-appropriate storage controls.

Deferred items remain those explicitly listed in the spec: visual workflow builders, generalized
plugin/optimization platforms, broad strategy/version matrices, enterprise administration, and
streaming/warehouse infrastructure. Missing initial acceptance evidence is not a deferral.
