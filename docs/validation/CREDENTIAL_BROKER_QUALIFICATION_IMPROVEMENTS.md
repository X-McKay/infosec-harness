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


### Latest full original-dataset rerun on ee6c1d8

The fresh rerun completed all 118 original cases across all eleven agents through
actual OpenShell executors and the zero-priced `llm.almckay.io` endpoint. It tested
source `ee6c1d84375b5b417951098faf49f23b5145d58c`, whose runtime bytes are identical
to `6578fe8`; the intervening commit changed only documentation. The source and
configuration remained frozen through actual terminal preservation. The run used
one repetition, concurrency one, the original 600-second case bounds and a
21,600-second outer bound. Actual execution and guards completed in 5,437.28
seconds. All original cases, goldens, scorers and qualification thresholds were
retained; no failed result was rescored.

**Full release: failed.** There were 114 semantic passes out of 118 cases, and ten
of eleven agent release gates passed. Environment planning was the only failed
agent gate. Its schema-validity metric was 0.9 against the required 1.0; its
accuracy, cost, request-count, budget and material-coverage gates passed.

| Agent | Cases passed | p95 requests | Original release gates |
| --- | --- | --- | --- |
| build-repair | 14/14 | 10 | passed |
| context | 14/15 | 5 | passed |
| env-planner | 9/10 | 7 | failed: schema validity |
| intake | 9/9 | 3 | passed |
| partial-build | 9/9 | 9 | passed |
| probe-author | 10/10 | 6 | passed |
| probe-diagnosis | 12/13 | 1 | passed |
| probe-planner | 9/10 | 2 | passed |
| probe-repair | 10/10 | 9 | passed |
| recon | 9/9 | 4 | passed |
| verdict | 9/9 | 1 | passed |

The previous build-repair, intake and probe-author gate failures did not recur in
this cohort. That observation does not establish that any single candidate
change caused the improvement. The previous full run remains failed and retained.

#### Remaining environment-planning failure

The failed case was
`an-empty-test-directory-must-not-send-the-planner-in-circles`. The evaluator
recorded `UnexpectedModelBehavior` / `no_accepted_output`, classified conservatively
as `invalid_output`. This differs from the prior unlabelled Maven-profile failure,
which passed in this cohort. The failed current case had seven directly retained
broker request references, three tool calls and three unclassified output retries,
with no repeated tool calls. Every referenced broker request completed. One
response ended with `length` at 16,000 output tokens, including only 123 reasoning
tokens; the other six ended with structured tool calls. These facts establish
truncation during this case, but the saved diagnostics do not retain exact
validator wording or establish which field/tool argument caused the rejection.
The metric name alone is not proof of a particular schema defect.

The smallest next investigation is the final/tool-output behavior for this exact
empty-directory regression, followed by a bounded correction and fresh targeted
and full qualification. Increasing timeouts, request limits or cumulative budgets
is not justified by this evidence. A reasoning limit alone would not address the
observed large non-reasoning output. Keep strict typed validation, original
expectations and retry limits.

Other semantic misses were the constant-only SQL caller in context (predicted
`reachable`, expected `unreachable`), diagnosis case `defect`, and the planner's
`deserialization-executes-code-and-still-needs-no-canary`. Their agent gates passed;
they remain wrong answers and are not relabeled as correct.

#### Candidate controls and terminal preservation

All eleven actual native readiness checks passed before model execution. The
fresh deployment used the previously attested immutable executor image and an
independently verified renewed TLS leaf with the same CA, key and extensions.
Only build-repair selected the `gateway-build-repair` backend with an authenticated
4,000-token reasoning limit. All 73 build-repair requests carried that limit and
returned structured tool-call parts; observed reasoning ranged up to 3,999 tokens.
This is actual full-agent broker evidence for that configuration, rather than the
previous isolated continuation. It does not imply that every response must reach
the cap. The other ten contracts were unchanged. Adding the backend changed the
whole-model-map configuration digest, which is retained explicitly.

Intake used the approved 32,000 per-request / 128,000 cumulative input limits,
with thinking disabled. Its 14 completed requests had a maximum input reservation
of 20,361; one exceeded the previous 20,000 ceiling. Its output maximum was 420
tokens, and no budget exhaustion occurred. This confirms the extra headroom was
used in this cohort without changing output or request-count limits.

Independent complete terminal preservation **passed**. Current state contained
2,567 requests, 679 budget roots and 848 deleted leases. All 413 new requests were
completed, and all 118 new budget roots and evaluation leases were retained.
Every prior 2,154 request, 561 budget and 730 lease-file hash remained unchanged.
Exactly the same fifteen historical unknown-completion requests and their holds
remained; there were no new unknown or pending completions, active leases, native
sandboxes, resource adoptions or resends. Both provider identities and exact
runtime/process/configuration fingerprints were unchanged. All 49 raw evidence
files, eleven reports and eleven independently checked completion witnesses were
retained. Read-only diagnostics made no model or lifecycle calls.

Initial diagnostic exporters incorrectly compared broker operator configuration
with source-dependent evaluation configuration. Those exports and their failure
were retained. The corrected exporter independently binds operator configuration
to the authenticated inventory and ledger, and case configuration to the frozen
case witness. All 413 request bindings then verified. This was an evidence-helper
correction; no runtime source, broker record or qualification score changed.

| Evidence | SHA256 |
| --- | --- |
| Frozen full118 plan | `749e15cd4814a25508ba006a0d3830171239a3b4db2d700f87764dd4f997a244` |
| Original full aggregate | `eaff249f379231935c9195faaddab1ee06149c4b1f4bb1d40ab7b5c21d49d6ed` |
| Model/runtime root proof | `a5ec24c128f787b26bed4b84b2a6019983536f77643a73dda017cfbc85778647` |
| Complete terminal state | `e0e7846aade02de2432b1a5ffa9fcea7918e278c783cc25c00a0bf3dedc7994c` |
| Terminal retention proof | `6c9b8096fe205e118885020a3b636bf8e01897db6609ca083985a732b43d8fad` |
| Read-only terminal root proof | `5a5b668bd4a87408e0d18eca1412f338b34c253b77c0a7e26a284823964bcb5d` |
| Verified numeric diagnostics | `c01bc03ae59aca46b3fdf5e0f0b88df6ecc5efe58ce2f8ebfac1b96cdcaa1cd5` |
| Exact two-case diagnostics | `314d952d1c147e16e0b1d222648c19915969923ed00bd158a3aebffae8b77653` |

Fresh canonical checks on the tested source **passed**: lint, compilation, agent
validation, generated governance/contracts, development-skill drift, and the full
deterministic suite (2,858 passed, 40 skipped). Existing PR backend, web and
conformance CI checks were green before this documentation update.

Fresh native22 (LocalOps11 + Temporal11), actual current Temporal-history replay,
production graph/replay/recovery, and hosted Kubernetes/Temporal/database/artifact
validation remain **not_checked**. Native22 and graph activation remain withheld
because full118 release failed. The old native bootstrap carrier's exact baseline
comparison also requires an explicit reviewed amendment for the new build backend
and intake limits before activation; the existing comparator must not be bypassed.
Actual pre-change history replay and failure-recovery evidence remain separate
requirements from synthetic compatibility tests or current-history replay. The
local endpoint did not require a provider credential, so real upstream credential
authentication is **not_checked**; deterministic replacement checks remain separate
evidence. Local UI checks are **not_applicable** to this model/configuration rerun.
Rollout remains disabled and the PR remains draft. This result-only documentation
update changes no behavior/provenance version or durable workflow semantics.


### Environment planner explicit installation candidate

Inspection of the seven exact saved broker responses resolved the latest failure:
the first `length` response called `repo_digest` with valid `{}` arguments; it
was not the final plan. The planner then called `read_files` and `load_capability`,
and submitted four byte-identical 282-character `final_result` objects. Every
object contained only `base_image`, `system_packages` and `test_command`.
`EnvironmentSpec` accepted their structure and supplied the default empty
`install_commands`. Offline replay against the original Java/JUnit5 fixture
reproduced exactly one violation: missing Maven provider warmup. The reconstructed
field-targeted feedback matched every saved retry byte for byte. Thus this is a
semantic repair failure, not malformed final JSON or truncated final output.
The earlier limited numeric diagnostic did not establish that distinction.

The candidate adds `PlannedEnvironmentOutput`, used only by env-planner, requiring
an explicit `install_commands` array. Its field description explains build-time
preparation and the real framework-specific Maven warmup. An explicit `[]` remains
structurally valid where no preparation is needed; Maven's unchanged semantic
guard still rejects it. `env` remains optional because its omission was not the
confirmed defect. No generated commands are inserted and no plan is silently
repaired. Shared/persisted `EnvironmentSpec`, other agents' output schemas, prompt,
retry limits, budgets, model settings, source policy and release thresholds stay
unchanged.

Env-planner advances from 1.0.4 to 1.0.5. New Temporal histories record the independent
`env-planner-output-v2` marker and use that activity identity. Old histories retain
`env-planner`, the exact byte-retained `agent-v1.0.4.yaml`, the original output
schema and matching resolved specification configuration. Host eager resolution
avoids workflow filesystem I/O. Both generations are registered. The legacy model
is replay-only, and an unrecorded old workflow frontier fails before reserving a
new invocation. Existing `maven-warmup-repair-v1` feedback is unchanged. Provider
single-dispatch, reservation recovery, retry, cancellation, settlement and lease
cleanup behavior are unchanged; no completed or uncertain request is resent.
Actual historical Temporal replay remains **not_checked**.

Canonical checks **passed**: lint, compilation, agent validation, generated API and
instruction/skill drift, development-skill drift and the full deterministic suite
(2,873 passed, 40 skipped). Focused regressions exercise the observed omission,
unchanged persisted defaults, explicit no-install decisions, unchanged Maven
warmup rejection, and a real SDK `FunctionModel` missing-field retry followed by
a valid prerequisite-preserving plan. Compatibility tests verify both registered
identities, one marker decision, matching configuration selection and refusal of
live legacy frontiers. These synthetic tests do not establish live model quality
or actual history replay.

Historical spec SHA256:
`a2904a70eea103633b1035e0b6c8f7879e27af2cd51a7ad638daca838b2a90c7`.
Retained investigation summary SHA256:
`2ed00cb3617eade21b08c201fe748ff08f20bd2030839e282e6ce0cf72a058f7`.
All nine packaged executor source hashes and the dependency lock match the
previously attested image; the host-serialized output schema does not change
`ExecutorContract`. The configuration digest changed, so the previous controller
process's cached admission policy could not qualify this candidate. The measured execution below
refreshed that process and established current source, TLS and readiness evidence.
The prior full118 failure remains retained and failed; the following results
supersede the pre-execution candidate status.

### Required install-command contract: measured broker evaluation

On source `438ec3da9e08f39b0501972d48ef7f224ec16207`, the original ten-case env-planner broker
evaluation **passed**. All ten cases passed, schema validity was 1.0, budget exhaustion was zero
and p95 request count was 8. The known Java/JUnit5 prerequisite regression passed. The original
cases, scoring rules, expected outcomes, budgets and release thresholds were unchanged.
Completion was independently checked against the persisted experiment and all ten case results;
static dataset coverage was not used as execution evidence.

The controller was refreshed for the changed env-planner configuration digest. Its initial
replacement stopped after starting the exact new controller because a private verification
command exceeded the operating system's argument-size limit. A separate read-only completion
verified that same controller and retained the failed replacement artifacts; it did not create
or restart another controller. One actual env-planner readiness lease then verified the current
contract and was ordinarily revoked. The passing model cohort's terminal preservation check
retained all 2,623 request records, all 689 budget rows, all 859 deleted lease files and the
original 15 uncertain requests. Native inventory remained zero and the two global providers were
unchanged.

Canonical checks **passed**: lint, compilation, agent validation, generated artifacts,
development-skill drift and the deterministic suite (2,873 passed, 40 skipped). Current-head CI
also **passed**: all six retained checks completed with SUCCESS against exact source
`438ec3da9e08f39b0501972d48ef7f224ec16207` (CI evidence SHA256
`4fb1404f1383e5361fab0794ddb2e2ca19e7f79731452806dd8ae5b06f848e47`). Actual historical Temporal
replay remains **not_checked**; the durable marker and legacy-frontier checks above remain
synthetic compatibility evidence.

Private evidence SHA256s:

- Model root: `3b0451a7ce4f592eccb39e17f6bc589af51f2d2d3456e6040b2960fc260a85c7`.
- Original report: `3fc4893c5d8bf281a7fd58476b0197643caf29b8096e31bb81c277fe03be1e71`.
- Persisted completion witness: `ef1c44499d7f8efe8fc2e04c289a55e77e732ee4337a026813fb3f95a1fcee16`.
- Terminal root: `ad67435d95895980d7e087f1ceba2950dd389a661099d030670d3c2cd1231ae5`.
- Whole terminal state: `ed76d81d43e201ccfc7fcc0980c3147923b8777de175635dff65c996e1ecdd70`.

A fresh all-eleven native readiness check **passed** after that terminal seal. It preserved all
request and budget rows, added exactly eleven ordinarily deleted readiness leases and sealed 870
deleted lease files. The separate original 118-case evaluation **failed and truncated** during
context case 15 after 14 passing build-repair cases and 14 saved passing context cases. That
case raised `BrokerError`; no context release report or later-agent reports were produced. The
model root retained a terminal-guard reconciliation failure. Read-only native metadata then
established an Error sandbox with `ControlSupervisorStartFailed`: its supervisor exited before
readiness, while configuration admission was accepted. The stored provisioning deadline was not
recorded as exhausted. The triggering supervisor failure remains unestablished; low-level debug
timeout text does not prove an exhausted deadline. All 136 newly admitted requests were
completed and the old 15 uncertain requests were unchanged. This does not establish complete
118-case qualification. It used one repetition, concurrency one, 600-second case bounds and a
21,600-second root bound.

An explicit, separately reviewed operator cleanup **passed**: two fresh observations confirmed
the exact Error sandbox identity, policy and current resource version, then only that sandbox
was deleted. Ordinary adapter revoke removed its recorded scoped ledger provider while the
lease's native ID remained empty. The cleanup preserved all 2,759 request records, all 718
budget rows, all 898 other lease files and the original 15 uncertain requests; all 899 leases
were `deleted` afterward, native inventory was zero and the two global providers were unchanged.
Its root evidence SHA256 is `4aee412d6c9407815b970fd9ac754f177330a323d16b8f093c6f95ca81218a8c`.
This cleanup does not establish the supervisor failure cause or make the failed evaluation pass.

A separate fresh read-only terminal seal **passed** after cleanup: all current request, state,
budget and lease maps were stable across two observations, the original historical subset was
unchanged, and no failed request was retried or adopted. The failed full118 cohorts remain
failed and retained.

Native22, graph, actual historical Temporal replay and hosted deployment remain **not_checked**;
rollout remains disabled and the PR remains draft.

Fresh full118 plan SHA256: `91457b2ffb86a3087ae621ba927f97ca233594c434cef1844e713b76667fa13e`.

Truncated full model-root SHA256:
`c27376ece012c6cc67145664a350955413c75575aef7beb043b172bedbfe123d`.

Final terminal root SHA256: `35adb7158b4706a183408080a744bec774c371ba15a27af3412e17d92c9ae61a`.

Final whole-state SHA256: `3b39a5066c0037db21add342f503f441b16dbbec3136ffab3437a6a5ea7966ac`.

The next qualification step is to establish why the supervisor exited before readiness, apply a
narrowly evidenced fix if needed, and run a fresh original 118-case cohort. No model budget or
release threshold change is supported by this failure.
