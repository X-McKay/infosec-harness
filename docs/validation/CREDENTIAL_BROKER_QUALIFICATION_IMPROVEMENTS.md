# Credential broker qualification improvements — 2026-10-02

Status: the b706e6d focused trial **failed**, with 30/36 cases passing; its broker completion and terminal retention checks **passed**. The subsequent JVM selector correction is implemented, with full live qualification **not_checked**. The prior full run remains failed (100/118 cases; four of eleven release gates passed). Focused results do not supersede the full-dataset gate.

## Scope and hypothesis

Use existing controls to resolve observed failures without adding a service or configuration framework: serial tool calls for environment planning and both build-repair agents; canonical recon output guidance; prerequisite-preserving build and Maven warmup guidance; bounded intake feedback for unsupported claims. The b706e6d endpoint-specific trial shared the existing non-thinking backend across intake, probe-diagnosis and verdict. The next reviewed configuration additionally routes build-repair through that backend; the other seven agents retain their default reasoning setting. Public default model routing is unchanged.

The b706e6d trial used recon 1.0.1, env-planner 1.0.2, build-repair 1.0.6 and partial-build 1.1.4. The JVM correction advances env-planner to 1.0.3, build-repair to 1.0.7 and partial-build to 1.1.5; recon remains 1.0.1. Broker specification is 0.2.10. Generated risk and system member references were regenerated from their declared sources. No wire protocol, output type/default/requiredness, evidence acceptance rule, scorer, golden expectation, request/token/cost budget or timeout changed. RepoProfile descriptions retain open ecosystem labels.

## Evidence and limitations

- `just check`, `just generated-check` and `just dev-skills-check`: **passed**.
- Full deterministic suite for b706e6d: **passed**, 2,662 passed and 40 skipped. The initial run retained three generated-version drift failures; regeneration resolved them without changing expectations. The subsequent JVM correction and additive review7 checks also **passed**, 2,730 passed and 40 skipped; lint, compile, agent validation, generated and development-skill checks passed.
- Regression tests exercise actual SDK request shaping for serial/default/parallel settings on direct and executor paths, structured output descriptions, closed feedback privacy, complete unsupported-claim removal and preserved evidence guards. Independent source review: **passed**.
- Real Temporal feedback history record/replay: **passed**, three isolated synthetic histories (legacy, new unsupported-claim marker and reference-repair-only). Replay made zero fresh model/provider calls. This narrow test is distinct from all-agent native replay.
- b706e6d fresh native OpenShell readiness: **passed**, all eleven contracts verified and cleaned up with zero provider calls. Focused trial: **failed**, 30/36. Full-dataset release, native all-agent qualification and graph: **not_checked** for this candidate and the subsequent correction.
- UI checks: **not_applicable**, no UI changes. Hosted Kubernetes/Temporal/database production deployment: **not_checked**.

The completed first live scope used the existing group selector: 36 original cases across nine agents, covering all 18 prior failures, two native failures, successful neighbors and related group cases. Original datasets, scorers and thresholds remain fixed. This is focused validation; it cannot establish full-dataset release. A new finite full 118-case trial requires reviewed corrections to the demonstrated runtime, schema and budget failures plus actual execution preflight and retention evidence. Focused subset threshold projections remain failed where applicable; they are not a full-dataset release gate. Original full-dataset thresholds and expected labels remain unchanged. Graph remains gated by the full and native results. The frozen baseline retains all 837 prior requests (822 completed and 15 uncertain), including budget state and unknown holds.

## Durable behavior and recovery

Intake uses a separate `intake-unsupported-claim-repair-v1` Temporal patch. Only two existing closed evidence diagnostics receive static guidance: literal location support and missing positive support. No report content, model value or source identifier is interpolated. The existing `intake-reference-repair-v1` range feedback and historical no-marker retry bytes remain unchanged. Whole unsupported claims must become null or receive literal positive support; null members and zero-confidence retained claims still fail validation.

Changed feedback alters subsequent model requests, so candidate runs require new frozen identities. Existing unique admission, persist-before-send, saved-result-before-acknowledgement, cancellation fences and conservative uncertain holds are unchanged. Completed records remain authoritative; old unknown requests are never resent or their reservations released by this work. Cancellation, cleanup and baseline preservation require observed runtime evidence. Prompt instructions are not execution permissions.

The executed synthetic Temporal helper recorded frozen-original unsupported feedback, current marked feedback and v1-only range feedback, then replayed with model execution forbidden. Its legacy validator comes from cdfe3bc2d8189cb2c76308699dd4de1f8f9d1445. Its passing result proves only retry-byte/marker compatibility, not production-agent or graph qualification.

Private evidence stays beneath `.harness/openshell-spike/live-qualification/`; secrets, provider bodies and source reports are not published here. Deterministic log SHA256: `35e237aa59686bf3b50ea5e90a00c8691b43cccd29a311c57b9006086a947912`.

## Focused outcome and subsequent correction

The frozen b706e6d trial repaired 13 of 18 previously failed eval cases. Including two additional native-failure fixtures, 15 of 20 unique historically failing fixtures now pass Local; this does not establish Temporal success. Partial-build passed 8/8, recon 6/6, intake 2/2 and verdict 2/2. All 167 new requests completed, with zero overruns or new uncertain outcomes. All 134 requests covered by serial-tool settings respected those settings; all nine non-thinking requests reported zero reasoning tokens. These checks use saved usage/results and offline SDK request reconstruction, not a new raw HTTP capture.

Six failures remain in the immutable trial: three unchanged semantic wrong answers (context, probe-diagnosis and probe-planner); Java build-repair exhausted its 16,000 output tokens in reasoning without an accepted answer; Java environment planning reached a budget stop after rejecting missing actual Surefire warmup and a path-valued selector; and a previously passing Perl case became `execution_not_checked` because host temporary storage was outside the Lima share. The precise rejected Java environment budget bound was not recorded and is not inferred.

Inspection confirmed an independent runtime contradiction: environment instructions and the shared field description required `{test_file}`, while JVM ecosystem guards require class selectors; Dockerfile validation also rejected valid class-selected commands. The correction distinguishes path-based runners from one named simple JVM class and requires policy/canary class agreement. Existing base-image, structural, module, package, environment, isolation and egress guards remain. Field types/defaults, scorers, golden labels and budgets are unchanged. Actual uncached JVM execution and the checkout-owned Perl temporary-directory correction remain **not_checked** until the separate zero-LLM preflight runs.

Terminal preservation **passed**: all 1,004 requests (989 completed and the original 15 uncertain) and all 283 budget rows are retained. All original 837 request rows and all 247 prior budget rows are byte-equivalent under canonical all-column hashing. All 36 observed leases were already deleted; native inventory is empty. Exact provider metadata, 347 historical lease files and ten primary service identities remain unchanged. A fresh PostgreSQL dump independently matches every current request and budget column. No service was stopped or deleted, no uncertain request resent, and no failed case rescored. Additive review7 qualification controls pin this terminal authority and preserve reviews1–6.

Selector validation runs in activities and introduces no workflow command or patch marker. New prompt/schema descriptions require fresh request and source identities; saved histories retain their original requests. Provider-forbidden replay for the final candidate and full native/graph qualification remain **not_checked**. The credential executor image can only be reused after its exact packaged source, lockfile and recipe hashes are freshly verified.

Private evidence SHA256:

- Focused aggregate: `5a108b7d9e1bfa4391b98f572b0b2e0ae491b7ba419b14a03a4d3194d0a3ade0`.
- Independent focused comparison: `0029511bf20d186f0f61fe10ed4cf547455a88b1ca9f9653478ed8a74e8cdc1b`.
- Terminal retention: `d383a402ad1029af60d05a9c33537d5bba925ba80c8bdf138e047ddde1915698`.
- Full current row-hash snapshot: `94bfbb9d73798b328f5f5bc1bcdb63a942c383de929a68ae1f23286db842f309`.
- Independent retained database dump: `78fab16fdd9de082f1532c37497bd56e06ed661b0f42138905c87ca3509ea049`.

JVM-correction canonical deterministic log SHA256: `27e2f97f22a0ecb28a1965b839397da116cf84809325a07ea8db4fe53a32184b`.
