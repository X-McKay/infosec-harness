# Credential broker qualification improvements — 2026-10-02

Status: implementation and deterministic checks **passed**; candidate live qualification **not_checked**. The prior full run remains failed (100/118 cases; four of eleven release gates passed). This candidate does not supersede those results until separately frozen live evidence is available.

## Scope and hypothesis

Use existing controls to resolve observed failures without adding a service or configuration framework: serial tool calls for environment planning and both build-repair agents; canonical recon output guidance; prerequisite-preserving build and Maven warmup guidance; bounded intake feedback for unsupported claims. The endpoint-specific operator trial shares the existing non-thinking backend across intake, probe-diagnosis and verdict. Public default model routing is unchanged.

Agent versions are recon 1.0.1, env-planner 1.0.2, build-repair 1.0.6 and partial-build 1.1.4. Broker specification is 0.2.10. Generated risk and system member references were regenerated from their declared sources. No wire protocol, output type/default/requiredness, evidence acceptance rule, scorer, golden expectation, request/token/cost budget or timeout changed. RepoProfile descriptions retain open ecosystem labels.

## Evidence and limitations

- `just check`, `just generated-check` and `just dev-skills-check`: **passed**.
- Full deterministic suite: **passed**, 2,662 passed and 40 skipped. The initial run retained three generated-version drift failures; regeneration resolved them without changing expectations.
- Regression tests exercise actual SDK request shaping for serial/default/parallel settings on direct and executor paths, structured output descriptions, closed feedback privacy, complete unsupported-claim removal and preserved evidence guards. Independent source review: **passed**.
- Real Temporal feedback history record/replay: **not_checked**, pending three isolated synthetic histories. This narrow test is distinct from all-agent native replay.
- Fresh native OpenShell readiness, provider compliance, focused trial, full-dataset release, native all-agent qualification and graph: **not_checked** for this candidate.
- UI checks: **not_applicable**, no UI changes. Hosted Kubernetes/Temporal/database production deployment: **not_checked**.

The first live scope uses the existing group selector: 36 original cases across nine agents, covering all 18 prior failures, two native failures, successful neighbors and related group cases. Original datasets, scorers and thresholds remain fixed. This is focused validation; it cannot establish full-dataset release. Full 118-case and native 22-case runs require acceptable focused evidence; graph remains gated by the full and native results. The frozen baseline retains all 837 prior requests (822 completed and 15 uncertain), including budget state and unknown holds.

## Durable behavior and recovery

Intake uses a separate `intake-unsupported-claim-repair-v1` Temporal patch. Only two existing closed evidence diagnostics receive static guidance: literal location support and missing positive support. No report content, model value or source identifier is interpolated. The existing `intake-reference-repair-v1` range feedback and historical no-marker retry bytes remain unchanged. Whole unsupported claims must become null or receive literal positive support; null members and zero-confidence retained claims still fail validation.

Changed feedback alters subsequent model requests, so candidate runs require new frozen identities. Existing unique admission, persist-before-send, saved-result-before-acknowledgement, cancellation fences and conservative uncertain holds are unchanged. Completed records remain authoritative; old unknown requests are never resent or their reservations released by this work. Cancellation, cleanup and baseline preservation require observed runtime evidence. Prompt instructions are not execution permissions.

A prepared synthetic Temporal helper records frozen-original unsupported feedback, current marked feedback and v1-only range feedback, then replays with model execution forbidden. Its legacy validator comes from cdfe3bc2d8189cb2c76308699dd4de1f8f9d1445. Even a passing result proves only retry-byte/marker compatibility, not production-agent or graph qualification.

Private evidence stays beneath `.harness/openshell-spike/live-qualification/`; secrets, provider bodies and source reports are not published here. Deterministic log SHA256: `35e237aa59686bf3b50ea5e90a00c8691b43cccd29a311c57b9006086a947912`.
