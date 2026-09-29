# Harness evolution implementation and validation

Implementation branch: `codex/harness-evolution`, based on develop `6dbb09e`.
Scope: the initial milestone in `HARNESS_EVOLUTION_SPEC.md` §15.0. Work is in progress;
this file records evidence and limits, not a release approval.

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
- A compare-and-swap root reservation ledger prevents concurrent allocation beyond configured
  ceilings. Interrupted or potentially retried provider work retains uncertain reservations.
- Findings, Workflows, Evaluations, Metrics, and Settings UI; neutral light/dark/system theme,
  shared shadcn-style components, active-run polling, honest errors/staleness/unknown values,
  evidence and review details, whole-population metrics, distributions, trends and stage breakdowns.
- Two canonical development skills and generated Codex/Claude copies; common checks; managed
  tool versions; isolated development project identities and editable application mounts.

## Validation evidence

These results are local development evidence, not release approval. Reports under `.harness/`
are ignored artifacts in this worktree. Stub scores are deliberately not quality gates.

| Check | Status | Evidence |
| --- | --- | --- |
| Full deterministic suite | passed | 1,445 passed with no skips or failures, including Buildx CSV options, safe image cleanup, older-Temporal accounting and writable disposable copies of sealed source snapshots; `.harness/validation/pytest-final.xml`. Wheel build errors now fail instead of silently skipping packaging checks. |
| Local Temporal | passed | Seven real-service tests cover acceptance before worker start, incremental output, component preparation, cancellation before/during work, root-budget exhaustion, and worker replacement; inference and sandbox activities are stubbed/mocked. Eight budget tests also cover older servers without root metadata and replay compatibility. `.harness/validation/temporal-final.log` |
| Backward replay | passed | Parent, preparation, and finding histories captured from unchanged `6dbb09e` replay against current workflows. `.harness/validation/histories/baseline-{0,1,2}.json` |
| All-agent eval machinery | passed | All 11 full datasets ran and persisted 118/118 cases; every command exited zero. `.harness/validation/final-implementation/index.json` links each report and log. This is not 118 successful security judgments. |
| Budget calibration machinery | passed | Two 3-case candidates plus a grouped 2-case holdout completed. Effective configuration, attempts, distribution summaries and limits are recorded. `.harness/validation/final-implementation/calibration.json`; dirty source correctly blocks promotion. |
| Eval source consistency | passed | Before/after captures, all 11 agent reports, and calibration share the digest recorded in `.harness/validation/final-implementation/index.json`. Future source changes require a new identity for comparisons. |
| Provider contracts | passed | OpenAI-compatible and Bedrock transports exercised through mocked tool-call and typed-output round trips, including effective settings and budget identities. |
| Persistence/metrics | passed | SQLite migration/model parity and downgrade, competing root reservations, 205-finding aggregate fixture, missing usage, failed/cancelled rows, and idempotent progress. Real PostgreSQL schema parity and head/0003/base round trips also passed; duplicate progress, concurrent reservations, review history, cancellation and metrics were exercised in a disposable PostgreSQL database. `.harness/validation/postgresql.log`. |
| Packaging | passed | Installed-wheel validation is included in the full deterministic suite. |
| Frontend | passed | TypeScript and production Vite build; desktop and 390px browser checks, light/dark themes, keyboard/zoom spot checks, real stub experiment reports, and explicitly synthetic Demo distributions. Histogram links match their exact filtered rows. Refactored evaluation views were verified again in-browser; nested latency observations render, subsecond values use milliseconds, and case percentiles match the backend nearest-rank method. The managed UI was also checked after restart: ready environment, actual exit-zero probe, seven agent invocations and durable event timeline rendered from the real Temporal result. |
| Generated artifacts | passed | OpenAPI/client schema, canonical Codex/Claude skills and instruction drift checks. Ruff and compilation pass. Handwritten frontend formatting is pinned and checked in CI; generated types are excluded. |
| Playbook structure | passed | Agent, skill, risk and system checks pass with the existing documented `AGENT029` waiver and warnings; `.harness/validation/playbook-conformance.log`. CI and development skills pin reviewed playbook revision `9e7fc03f2e1253be3e2adea10663ddf429646cea`. Structural conformance does not prove behavioral adherence. |
| Managed macOS runtime | passed | On this Apple Silicon host, a fresh checkout-owned VZ VM ran the actual isolated build and probe through API/Temporal, persisted ready-environment evidence and nonempty root-budget operations, and passed S3 put/get/delete. Actual no-network and proxy allow/deny/private/direct checks passed; a fresh production builder verified runsc, sole internal network and exact proxy configuration. PID exhaustion and an OOM kill demonstrated enforcement; CPU quota was inspected. `.harness/validation/runtime-smoke.log`. Stop followed by warm `./dev` preserved the same validated batch and S3 sentinel; `.harness/validation/runtime-warm-start.log`. This is not clean-host OS acceptance. |
| Clean Linux onboarding | not_checked | QEMU/KVM bootstrap implemented; no clean Linux host execution has been performed. |
| Live OpenAI-compatible profile | not_checked | `/v1/models` identified `Qwen3.6-35B-A3B-NVFP4`; the inference sweep awaits explicit payload-egress approval. |
| Live Bedrock | not_applicable | Explicitly excluded from this validation by the user. Mocked contract coverage remains required and passed. |

The live sweep was rejected by automatic approval review because it transmits repository-derived
agent-evaluation prompts and fixture content to `https://llm.almckay.io`. Explicit payload approval
has been requested. The rejected action was not retried or bypassed.

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
- Worker replacement and explicit cancellation are covered. Exhaustive process-loss resource
  reconciliation and every historical workflow branch are not covered by these scenarios.
- Automatic prepared-image eviction is disabled: age alone cannot establish that a workflow
  has finished using an image between activities. Manual cleanup no longer force-removes images
  and requires quiesced assessments. Durable image leases and bounded automatic retention remain
  incomplete; images can accumulate. This preserves active resources without claiming SNAP-04's
  full cache-lifecycle implementation.
- Comparable release gates require clean, identical source provenance. Comparisons across
  intentional source changes are currently descriptive and cannot establish promotion.
- Browser spot checks are not a screen-reader/accessibility audit or a clean-host usability study.
  Skill structure and generation checks are not a comprehensive activation/adherence study.
- Prompt and binary content are excluded from default model telemetry. Evidence records still
  intentionally contain assessment output and require deployment-appropriate storage controls.

Deferred items remain those explicitly listed in the spec: visual workflow builders, generalized
plugin/optimization platforms, broad strategy/version matrices, enterprise administration, and
streaming/warehouse infrastructure. Missing initial acceptance evidence is not a deferral.
