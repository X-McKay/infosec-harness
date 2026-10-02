# Credential broker qualification improvements — 2026-10-02

Status: the 5d3b268 full v9 candidate **failed** and was truncated during probe-planner: 85/88 scored cases passed. Six completed agents passed their release gates; partial-build passed all semantic cases but exceeded the unchanged request-count gate. Operator cleanup and full terminal preservation **passed**. Native all-agent and graph qualification remain **not_checked**. The next minimal cancellation and discovery-guidance corrections require fresh qualification; prior failed trials remain authoritative and are not rescored.

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

Inspection confirmed an independent runtime contradiction: environment instructions and the shared field description required `{test_file}`, while JVM ecosystem guards require class selectors; Dockerfile validation also rejected valid class-selected commands. The correction distinguishes path-based runners from one named simple JVM class and requires policy/canary class agreement. Existing base-image, structural, module, package, environment, isolation and egress guards remain. Field types/defaults, scorers, golden labels and budgets are unchanged. Actual uncached JVM execution and the checkout-owned Perl temporary-directory correction subsequently **passed** the zero-LLM preflight at 4307c7c, after the Maven proxy correction below.

Terminal preservation **passed**: all 1,004 requests (989 completed and the original 15 uncertain) and all 283 budget rows are retained. All original 837 request rows and all 247 prior budget rows are byte-equivalent under canonical all-column hashing. All 36 observed leases were already deleted; native inventory is empty. Exact provider metadata, 347 historical lease files and ten primary service identities remain unchanged. A fresh PostgreSQL dump independently matches every current request and budget column. No service was stopped or deleted, no uncertain request resent, and no failed case rescored. Additive review7 qualification controls pin this terminal authority and preserve reviews1–6.

Selector validation runs in activities and introduces no workflow command or patch marker. New prompt/schema descriptions require fresh request and source identities; saved histories retain their original requests. Provider-forbidden replay for the final candidate and full native/graph qualification remain **not_checked**. The credential executor image can only be reused after its exact packaged source, lockfile and recipe hashes are freshly verified.

Private evidence SHA256:

- Focused aggregate: `5a108b7d9e1bfa4391b98f572b0b2e0ae491b7ba419b14a03a4d3194d0a3ade0`.
- Independent focused comparison: `0029511bf20d186f0f61fe10ed4cf547455a88b1ca9f9653478ed8a74e8cdc1b`.
- Terminal retention: `d383a402ad1029af60d05a9c33537d5bba925ba80c8bdf138e047ddde1915698`.
- Full current row-hash snapshot: `94bfbb9d73798b328f5f5bc1bcdb63a942c383de929a68ae1f23286db842f309`.
- Independent retained database dump: `78fab16fdd9de082f1532c37497bd56e06ed661b0f42138905c87ca3509ea049`.

JVM-correction canonical deterministic log SHA256: `27e2f97f22a0ecb28a1965b839397da116cf84809325a07ea8db4fe53a32184b`.


## Maven build proxy correction

The first actual zero-model execution preflight **failed** before dependency warmup: Maven attempted direct DNS for approved Central instead of consuming the supplied HTTP proxy. Direct DNS remained blocked by the build network. The failed build's exact issued target tag was confirmed absent; before/after database and primary-service retention passed, with zero provider calls. Perl execution was not dispatched in that preflight.

The correction adds build-RUN-scoped Maven JVM options using only the existing validated operator proxy, including native Resolver's explicit `aether.connector.http.useSystemProperties` opt-in. Existing `MAVEN_OPTS`, settings files, mirrors and install-command arguments are preserved. Network restrictions and destination allowlists remain unchanged. Image format advances from 2 to 3 and Maven target identity includes the validated proxy address, preventing reuse after changing that address. The observed base is Maven 3.9.16; real build and control checks subsequently **passed** the separate zero-model execution preflight at 4307c7c. Component evidence does not qualify older or custom transports or Gradle.

Rendering and image identity run in activities, so this correction adds no Temporal workflow command or marker. Completed activity results and saved image tags remain authoritative. Pending activity retries may produce the new image generation and must record fresh runtime provenance; they do not authorize resending provider requests or rescoring previous outcomes. Full native provider-forbidden replay remains **not_checked**.

Maven-bridge canonical checks **passed**: lint, compile, agent validation, generated and development-skill checks, with 2,746 deterministic tests passed and 40 skipped. Deterministic log SHA256: `9f1546436ef21a7e4b52977db3e891861531df8a2876b3195a77e26d0bed196e`. Actual runtime preflight subsequently **passed**; the full v7 candidate **failed** and was truncated as recorded below.


## Full v7 outcome and next correction

The 4307c7c candidate first passed actual zero-model execution preflight: fresh uncached Maven and Perl builds, four positive/negative canary executions, and the Perl DBI/SQLite dependency check. Eleven native contracts passed readiness and cleanup, four build-egress controls passed, and six CI checks passed. This qualifies the observed Maven 3.9.16/Resolver 1.9.27 build path, not other transports or a hosted production deployment. Preflight proof SHA256: `f3a0a9a2ba1e2ce661f2797e9965a1fc0c216a203f57ac6a8dab847ea64fcfd2`.

The frozen full candidate kept all original 118 cases, scoring rules and budgets, with one repetition and concurrency one. Build-repair passed 11/14 but failed budget, execution and request-count gates; context passed 14/15 and its release gate; environment planning passed 9/10 but failed schema validity; intake passed 8/9 but failed the budget gate. Partial-build scored four passing cases, then stopped on an identity rejection during case five. Its remaining five cases and the six later agents were unmeasured; no partial release report was written. The failure must not be described as a model timeout or a completed 118-case qualification. Aggregate SHA256: `29f0ee04cd9de9fa45bfdd50cd964b33d101c8a2ef8e3b190d537d72c4879a95`.

The new build failures included omitted compiler/dependency prerequisites and repeated capability loads despite existing already-active feedback. The Java scope-driver case and Perl install-prefix case passed. Environment planning repeated the same schema-valid proposal with empty install commands despite missing-warmup feedback. Intake produced a reversed source range before a closed broker budget rejection; the exact rejected sub-bound was not recorded and is not inferred from completed token usage. The next reasoning-mode comparison must retain the earlier Java reasoning-only output-cap failure as counterevidence.

The failed preparation left one quarantined lease with no admitted request and no saved native ID. Current control-plane observations had a unique sandbox ID, exact five ownership labels and accepted policy, but no Ready workload. These current observations do not prove what the earlier creation check saw. A separately reviewed, one-off operator reconciliation verified the persisted creation intent, actual labels, policy, provider identity and absence of containers; it backed up the original private lease, assigned identity only for ordinary revocation, and deleted only that sandbox and its scoped credential. Runtime automatic adoption and readiness rules were unchanged. Operator cleanup proof SHA256: `f8914725d45eb8ee6337fb558f1abd7fa868764b5b0ad4ae3c495eacb02a8869`.

Terminal preservation **passed**: all 1,285 request rows and 336 budget rows are retained; the 281 new requests completed, with zero new unknown outcomes. Every original 1,004 request and 283 budget row remained unchanged, as did all 15 unknown holds and 405 historical lease records. A fresh PostgreSQL dump independently matched every current column. Exact controller/database identities and volume, both global providers, the gateway and ten primary services were preserved; native inventory is empty. The failed-preservation backup and failed/truncated outcomes remain retained.

- Terminal proof: `8327cd21fedd4957750dd4deac2f6128ac44904c2e142bf0a041e9b701d22157`.
- Whole current snapshot: `971c849903a71203767083c2a8549e47e9bd50cd8316cea78662519166cf19c2`.
- Independent database dump: `e49a79bc27a0643a8baa8a603295f330f5829abe5484cf70907c3e1a8fe14cde`.
- Independent runtime/dump proof: `2101ba7325e963b7800074304c1493bf185f05201a89db32414ef935d31ec84c`.

The next code correction changes only existing missing-Maven-warmup retry text: it names `install_commands` first and presents the existing declared-framework command while preserving prerequisites. The `maven-warmup-repair-v1` Temporal patch applies only when feedback actually changes; historical no-marker retry bytes and unchanged wrong-framework feedback are preserved. Env-planner advances to 1.0.4, build-repair to 1.0.8 and partial-build to 1.1.6 because they share this validator. Acceptance, schemas, command constants, budgets, scoring and runtime isolation are unchanged. This remains a measured hypothesis, not proof of improved model quality.

Controller-only logs now identify fixed native lifecycle and budget rejection guards without exception strings, identities, credentials or provider bodies. They preserve error codes, remote responses, allocation rules and denial behavior. No new service or wire format is introduced, and the inference executor's packaged source remains unchanged. Existing requests and uncertain allocations retain their original identities and dispositions; no provider resends or automatic retries are authorized by these logs. Actual final-candidate native replay, full release qualification and graph execution remain **not_checked** until their gates pass.

Warmup/diagnostic canonical checks **passed**: lint, compile, agent validation, generated and development-skill checks, with 2,792 deterministic tests passed and 40 skipped. New regressions cover framework-preserving repair convergence, historical feedback bytes, marker eligibility, native identity denial without upload/dispatch, and budget denial before ledger mutation. Log SHA256: `46570a955b71360fc59d2c032695a225005586105e5ce98f00fbf870948606a8`. Actual Temporal feedback replay **passed**: two isolated synthetic histories (legacy without the new marker, and current with it) completed and replayed with zero fresh FunctionModel or provider calls; four synthetic activities ran only during recording. Both owned workflows completed and workers stopped without service resets. Evidence SHA256: `132a4c60c797c0b1d1241c72adae158891ab9fd12023ef2beaa6413db2be5653`. This is narrow feedback compatibility evidence, distinct from all-agent native or graph qualification. UI checks are **not_applicable**.


## Full v8 TLS failure and full v9 outcome

The first 5d3b268 full trial (v8) failed before model dispatch because its private worker trust root had expired. The retained server leaf was still valid. Verified TLS reported certificate expiration; zero new model requests were admitted. Terminal preservation passed. This was a qualification-fixture certificate failure, not evidence of an LLM endpoint fault.

A separately reviewed fixture renewal preserved the existing CA key, subject and extensions and kept the server leaf unchanged. Actual host and native sandbox canaries both reached authenticated endpoints with hostname and chain verification enabled; neither made a model request. All prior ledger rows and lease files remained unchanged. This establishes the tested trust path, not a general production certificate-rotation feature. Subsequent worker configuration changed only its CA file; all eleven immutable contracts matched the serving controller.

The fresh full v9 trial retained all original 118 cases, scoring rules, request/token/cost budgets and thresholds, with one repetition and concurrency one. It used the local zero-priced Qwen endpoint through OpenShell, with build-repair restored to its default reasoning setting. The measured outcome was:

| Agent | Scored cases passed | Release gate |
| --- | --- | --- |
| build-repair | 14/14 | passed |
| context | 14/15 | passed |
| env-planner | 10/10 | passed |
| intake | 9/9 | passed |
| partial-build | 9/9 | failed: p95 requests 13, maximum 12 |
| probe-author | 10/10 | passed |
| probe-diagnosis | 12/13 | passed |
| probe-planner | 7/8 scored; ninth attempt unscored | failed/truncated |
| probe-repair, recon, verdict | unmeasured | not_checked |

The context constant-only-sink case still predicted unknown instead of unreachable; probe-diagnosis still misclassified the defect case; the scored planner deserialization case chose a canary file instead of marker output. These original semantic failures are retained. Passing build cases and environment warmup do not establish a causal model-setting comparison across the different trials.

The unscored planner attempt failed during native provisioning, before any inference request was admitted. Its persisted lease had no native ID, while the current control plane showed a unique sandbox with the exact name and all five ownership labels. The actual retained Ready condition reported `ControlSupervisorStartFailed`: the supervisor exited after a 30-second idempotent boundary-control timeout. That message is shared by multiple control operations, so it does not identify whether confirmation, agent launch or another control exchange stalled. The discarded original CLI stderr cannot be reconstructed. A longer provider-model timeout would not address this pre-inference failure.

Ordinary revocation correctly refused the missing persisted native ID. A separate one-off operator cleanup verified accepted policy, provider identities and attachments, exact ownership, and zero remaining containers; it backed up the original private lease before supplying identity solely for ordinary revocation. No automatic adoption, readiness, dispatch or model retry was introduced. All 1,641 request rows and 425 budget rows remained unchanged, including the failed invocation's zero-request budget root and all 15 older unknown holds. All 356 new requests completed; there were no new unknown outcomes. The other 558 lease files, both global providers, database volume, gateway and ten primary service identities remained unchanged. Native inventory is empty. An independent PostgreSQL dump and a separate read-only snapshot matched every retained column.

The failed trial's evidence was sealed before source changes. The full release gate remains failed; native all-agent replay and graph execution were withheld. Hosted deployment remains not_checked; UI checks remain not_applicable.

Private evidence SHA256:

- Full v9 aggregate: `d99a516f4c679422924d9aa31191a3c70019b02262b14fea8f9efe366149bee5`.
- Read-only full-state diagnostic: `3b7f75c8923c62adbcc9beb98bf3b23435f7c9d10e090f2d91ed56a1eda0e5e9`.
- Exact orphan policy/startup observation: `cb40fad4bebf02d7e768b4c361feb7c0147b3d2c645c279bb8db152efac93d8d`.
- One-off operator cleanup: `36f04c6e681f24acdc2ef8b5a607f464f1d92d89147527affad9ccd291206346`.
- Terminal retention: `5d7b86f4bb9a141367a59f582698a0d8a1026e61233dde266ad5b5ab64c40f4b`.
- Whole 1,641-request/425-budget snapshot: `ed8c478c015830c5e06901d1ea34091e85cc8f8e07cdf5a50b62a330207487ab`.
- Root runtime seal: `d519007facbe6b17d3e40d259c8c97fe0e28a179b1bbee6b05c7007aba633546`.
- Independent reviewed-reference pin/source-freeze release: `0361c8ad15cb544cb797b2a7156c61b5e24e4c6b3086ac4630e53c83c56d6a80`.

## Minimal follow-up corrections

An independently confirmed cancellation defect affected native CLI ownership: controller preparation can cancel at 90 seconds while the thread-running create subprocess continues toward its 120-second timeout. The correction uses one shared async subprocess helper, shielding process acquisition and cleanup, killing the exact owned process group and reaping it before propagating cancellation. Killing the CLI is never treated as proof a native mutation was rolled back. This correction does not claim to fix the separately observed 30-second supervisor timeout. Actual local process regressions cover timeout, cancellation during spawn and reaping, repeated cancellation, and descendants surviving an exited leader; fresh native efficacy remains not_checked.

The partial-build request-count failure has a concrete, smaller correction: reuse already returned directory and manifest results, treat a missing directory as a completed discovery result, and stop broad repository searches once the owning declarations are complete. The worst v9 case used twelve tool calls plus its final model answer, including a repeated identical directory census and unrelated broad globs after the owning manifest was already known. Partial-build advances from 1.1.6 to 1.1.7; prerequisites, unresolved outcomes, required truncated-range reads, schemas, goldens and budgets remain unchanged. This is a prospective efficiency improvement, not measured gate success. Fresh focused and full trials must establish its effect.

These changes introduce no new service, wire protocol, output format or workflow command. Controller cleanup remains fail closed. No completed or uncertain provider request is resent, no old reservation is released, and no failed case is rescored. Generated governance comes from the canonical versions. Canonical checks and fresh live qualification for this follow-up must be recorded before acceptance.


The next startup candidate adds fixed control-kind timeout diagnostics and a 60-second ceiling only for boundary confirmation and agent launch. Other control waits and the single-envelope idempotent retry behavior remain unchanged. Preparation is bounded at 120 seconds, with worker540 below the unchanged activity600 ceiling. This is an explicit buffered experiment, not a measured resolution of the v9 stall. It requires fresh supervisor and executor image identities, actual zero-model readiness/cleanup evidence and new qualification manifests; prior native drafts must not be activated. See [timeout rationale](CREDENTIAL_BROKER_TIMEOUTS.md) for the nested walls and reduced outer margin.


Follow-up canonical checks **passed**: lint, compile, agent validation, the deterministic suite (2,805 passed, 40 skipped), generated-artifact checks and development-skill checks. Log SHA256: `36c1a04cee39f0469aa46296ecf30a0006c5d93ef45ebf2513fee153a51b76dd`; source-bound check proof: `84a79a023d21afde272b33a741d831f63a966d4ad866c83c7b4528ff307dc6cf`. Fresh actual runsc positive/negative, PID/memory bounds, build-egress allow/deny and builder/fixture cleanup checks **passed**, preserving all 1,641 requests, 425 budgets and primary service identities; proof: `db6ae30bb20d25ff3ef4e085e2fae3c78df5a162a6532cbe128762a61ecbcb8f`. These checks do not establish Rust test execution, the new native image's startup behavior, full release qualification, or hosted deployment; those remain **not_checked** pending actual build and fresh trials.


### First fresh-image build checks

On source `2ebe9aa`, the supervisor's original provider-readiness/network tests and all five new startup-control regressions **passed**. The build then **failed** at the upstream exactly-once boundary-replay test: its fixture takes the current UID/GID, and the root build process supplied zero, which the workload identity validator correctly rejects. This is a test-runner fixture failure; the identity guard and assertions remain unchanged. The next recipe compiles the same test and executes it with an explicitly unprivileged identity. No supervisor image was qualified. Retained failed build proof: `65b334d9615a1c9167ff919a13d03a2a53435ba8b747aca27596ba3e4b260458`.

The fresh minimal executor built and loaded, but its validation helper **failed** before creating an attestation container because it expected Docker's image ID to equal the config-blob digest. This daemon reports the OCI manifest digest; actual archive and image configuration matched. A separate check must verify the manifest-to-config/layer chain and the bytes inside that exact existing image, without rebuilding or reloading it. The failed attestation remains retained: `527de54b2a07d721c2cab7d449b61fb8b42aeb61552c7fdcc494aca1b98e303d`.

Both terminal checks preserved all 1,641 request records, 425 budget records, historical uncertain holds and existing service identities. Neither attempt made a model call or activated new contracts. Fresh readiness, focused/full agent gates and all-agent native qualification remain **not_checked**.

### Completed full original-dataset qualification on 1579c05

All 118 cases across 11 agents completed through the actual OpenShell broker and the zero-priced `llm.almckay.io` endpoint. The unchanged full release gate **failed**: build-repair had one reasoning-only output at its 16,000-token response limit; env-planner exhausted semantic output repairs for an omitted Maven warmup; intake had two input-reserve admission stops; probe-author exceeded its p95 request threshold (13 versus 12). The other seven agent release gates **passed**. No threshold or expected result was changed.

The independent read-only terminal seal **passed**. All 2,139 request records and 552 budget records were retained, including 434 newly completed requests and all 15 historical unknown-completion requests. There were no new unknown completions or active leases. Every original report and completion witness was retained and cardinality validated for all 118 cases. Whole-state proof SHA256: `1c9556a26244d51fa07e35d1d5c97ef9108e2df1e30e0fc5e435b0ecee148a9b`; retention proof: `9dec3e935e1e6f668fb9d419d9442fb5f78abe38ec0305d226e44e6d746431e6`; root terminal proof: `b4ac29ad881dd72a5ea44212037452769e4702ff85b6e8115f99a1de86437e22`. Native22, graph qualification, real durable replay, and hosted deployment remain **not_checked**; failed full gates do not authorize promotion.

### Optional reasoning limit and intake repair candidate

The shared OpenAI-compatible adapter now supports an optional typed `thinking_token_budget`, authenticated in the executor contract and operator profile. It must be positive, smaller than the effective total response cap, and compatible with enabled reasoning. Its omission preserves historical serialized identities. Both direct and executor paths emit the same top-level provider field; arbitrary caller overrides remain rejected. This additive control requires fresh image/source/profile qualification before broker use. Existing holds and request identities are never rebound.

The deployed vLLM 0.30.0 server accepted a 32-token reasoning limit and returned a correct structured tool call after 31 reasoning tokens. A separate saved build continuation with a 4,000 reasoning-token limit returned a schema-valid final result using 573 reasoning tokens; offline semantic and structural checks **passed**. That continuation did not hit the limit and does not establish that the cap caused the improvement or that the full agent qualifies.

Intake's two stops were independently confirmed as `admission/input_reserve` in actual controller logs. They occurred after two requests, with only 62,003 and 61,001 of 144,000 invocation tokens held. Actual output totals were 457 and 1,010 tokens, with zero reasoning. The preceding proposals respectively reversed a source range and retained unsupported line numbers. Offline reconstruction through the pinned SDK and actual validator measured the next input reserve at 21,465 and 20,680, above the old 20,000 ceiling. These are reconstructed requests, not saved rejected-request attestations. The candidate intake ceiling is 32,000 with consistent cumulative input of 128,000; four requests and aggregate output of 64,000 remain unchanged. Full nine-case candidate model quality and broker qualification are **not_checked** until the fresh controlled run completes.

The integrated intake v4 and reasoning-cap candidate passed canonical lint, compilation and agent validation, generated contract and development-skill drift checks, and the full deterministic suite (2,858 passed, 40 skipped). The installed-wheel tests verified the retained v3 specification and registration of all four intake generations. These offline checks do not establish actual Temporal replay, live candidate intake quality or hosted deployment; those remain **not_checked**.

### Targeted intake v4 qualification on 6578fe8

The fresh evaluation through the actual OpenShell broker and zero-priced
`llm.almckay.io` endpoint **passed** all nine original intake cases once. The
independent persisted completion witness matches every frozen case, repetition,
configuration and budget identity. Every unchanged intake release check passed:
task success and schema validity were 1.0, p95 model requests was 3, budget
exhaustion was 0, and uncovered material scenarios was 0. Both previously failing
injection-report cases passed. The complete model run and runtime guards took
142.59 seconds.

This tested intake 1.0.4 with 32,000 input tokens per request and 128,000 cumulative
input; four requests and 64,000 cumulative output remained unchanged. Reasoning
was disabled and the optional thinking cap was absent. This combined candidate
pass does not isolate which improvement caused each case to succeed or establish
that every future repair fits. No original failed report was rescored.

The fresh executor image
`sha256:242f528c2f4b644c61227600f644de6dad74b870a175f94db58f2bc95880c6b7`
passed immutable source/layer and unprivileged import checks. The actual new
controller passed TLS/authentication and source/configuration checks; targeted
intake readiness and ordinary cleanup passed before model calls. Initial image
permission and qualification-helper failures were retained and corrected before
this cohort; they are not reported as successful attempts.

Independent read-only terminal retention **passed**. All 2,154 requests and 561
budget rows were stable across two snapshots, including 15 newly completed
requests and nine new budget roots. Every prior 2,139 request and 552 budget row
was unchanged. All 719 leases were deleted, including the nine evaluation leases;
all prior 710 lease files were unchanged. Native sandbox inventory was empty,
provider metadata was unchanged, and the 15 historical unknown completions and
their holds remained intact. There were no new unknown completions or adopted
resources. The tested source remained frozen through terminal retention.

| Evidence | SHA256 |
| --- | --- |
| Intake report | `0936c825aefaf1a15f0ee5a85e2e530eeb1565bc0a40f584a8651a1a414d1871` |
| Completion witness | `3352edb93fe286ab3438b478be2cdceedff2b649aa2afbf7f86ea73d972479ec` |
| Aggregate intake gate result | `b3252d72b1843a144fb53eb6f1e11c9126419676808f555820f351337bc08a53` |
| Model/runtime root proof | `8c6b9d23d3425fdd53bc55a5784985c6737a91ff91a5a0cdb7bdcc8ba58670d0` |
| Whole terminal state seal | `7859e11d97b7c1e8864f0e67bdc34d973d1bc34e074efaab4f0688271f5010cd` |
| Read-only terminal root proof | `0385aea5d290269e43463d8c7b5a709f097ddb37f460985e235acf0fb461b3a2` |

The previous full118 release gate remains **failed**. Current full candidate
release, native22/graph qualification, actual historical Temporal replay, and
hosted deployment remain **not_checked**. The optional reasoning cap is not
qualified by this non-thinking intake run. UI checks are **not_applicable** to this
intake-only change. Rollout remains disabled and the PR remains draft.
