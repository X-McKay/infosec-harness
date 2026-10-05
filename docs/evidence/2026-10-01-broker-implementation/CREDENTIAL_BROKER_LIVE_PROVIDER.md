# Local-provider credential broker qualification

Status: direct live pilot passed; native live qualification failed and is fenced; corrected direct full workflow passed; native policy-generation trigger unresolved. Rollout remains disabled.

## Frozen scope and authorization

The user authorized `<self-hosted-endpoint>` with no monetary limit because it is locally hosted. The existing catalog assigns `Qwen3.6-35B-A3B-NVFP4` zero input/output prices. The October 1, 2026 model-list response reported that sole model, NVIDIA model root, and a 131,072-token context. This is provider metadata; it does not attest deployed weights, tokenizer revision, or upstream authentication. The endpoint accepted model discovery without authentication.

The private manifest was frozen before inference at source commit `b6f911221a1c61edf3e77be1cba164dbe77529ad`, SHA256 `b41fb7a2bd695825bd2eff8b613f052e8c1319ad35bd053997c1a58cc1a20745`. It selects eleven existing cases, source dataset hashes, direct catalog, native catalog references, one concurrent trial, a two-hour root deadline, unchanged agent safety limits, provider retries zero, and the existing 16,000-token output floor. Ground truth and scoring callbacks remain host-only. Failed attempts are retained; limits and expectations are not relaxed after a trial. All model tiers map to the same model.

| Agent | Frozen case | Direct requests | Direct result |
| --- | --- | ---: | --- |
| intake | sql-injection-from-prose | 2 | passed |
| recon | python-pytest | 3 | passed |
| env-planner | python-pip-pytest | 4 | passed |
| build-repair | missing-system-library | 5 | passed |
| partial-build | narrow-after-repeated-full-build-failure | 4 | passed |
| context | sqli-vulnerable | 3 | passed |
| probe-planner | sqli-can-inspect-the-result | 2 | passed |
| probe-author | sqli-marker-oracle | 4 | passed |
| probe-diagnosis | positive | 1 | passed |
| probe-repair | asserts-before-reaching-the-sink | 8 | passed |
| verdict | valid_positive_sqli | 1 | passed |

## Direct baseline

All eleven registered agents produced their expected typed outputs and passed the existing deterministic semantic scorer. The direct trial used 37 observed requests, 163,285 input tokens and 14,725 output tokens; summed case time was 180.052 seconds. The private report is `live-qualification/reports/pilot-4622e888101c4c7f800a3bc81593c1fe/direct.json`. These are compatibility cases rather than a statistically adequate quality comparison. Actual tool names and usage are retained in the private report; the baseline does not by itself establish full sandbox build/probe execution.

## Admission defect found before native dispatch

Independent primary-tokenizer analysis found two valid payloads which exceed the former raw UTF-8 plus fixed-padding estimate: 5,000 Unicode combining-diaeresis characters yield 15,010 template tokens against a 12,618 reservation; a tool description with 5,000 CJK characters yields 25,248 tokens against a 19,020 reservation. NFC normalization and chat-template JSON escaping make the former estimate unsafe for the published Qwen tokenizer/template. Native dispatch was paused before sending live broker requests. The candidate now measures actual pinned SDK shaping before applying the independently qualified normalization and template bound. Controller and executor must use the same rule and a new immutable executor image/contract.

Qualification of published artifacts and qualification of the actual deployed tokenizer remain distinct. Model discovery cannot satisfy the latter gate. Existing held allocations and saved request identities are retained; a changed image does not authorize redispatch or accounting release.

The initial private catalog conflated cumulative input allocation with request context admission. Before native inference, a separate explicit profile request cap was introduced. Native request caps are at most 100,000 input tokens and at most each authored agent's request-context ceiling; actual immutable output settings independently fit the reported context. Cumulative input/output/request budgets use the ordinary resolved agent limits. Operator binding amendments are retained separately from the original frozen case manifest. Regression coverage checks omitted-profile identity compatibility, cap precedence, invalid values, multiple held requests exceeding one request's allowance, and oversized-request denial without additional allocation.


## Native pilot and retained failure

Before any native call, all eleven baseline comparisons verified exact endpoint, model, effective settings, authored budgets, pricing backend, custom-price digest and GenAI pricing-table identity. The complete models YAML digest differs because the native configuration adds transport bindings; both full identities are retained rather than compared as if they were price values. Changed prices, price-table versions, endpoints, settings or budgets remain admission failures.

The production controller rejected unsigned TLS requests with HTTP 401. Actual native policy, provider attachment, immutable image and process confinement were independently verified for all eleven contracts with one lease at a time and no provider calls. The final admission image is `sha256:94cd2e3e7e981d14148d23c94492af004b00162e203bcac66aff7577d0f79862`.

The first native LocalOps pilot was stopped after a common post-claim failure. Intake, recon, environment planner and the cancelled build-repair attempt each retain one `completion_unknown` request: four dispatch permits, no committed result or usage, and retained root allocations. Scoped closure passed for every started invocation and the worker was reaped. A claim is dispatch authority, not evidence that an upstream response completed. These requests must never be resent; the trial cannot establish actual provider request count or cost. Temporal native compatibility has not yet run. Private terminal report: `reports/pilot-3e2488d9af7a4192af8dc1e33652e2f6/report.json`.

## Full production workflow trials

The first direct production Temporal graph completed inconclusive because generated Docker build inputs were placed in the host temporary directory while the managed Docker CLI executes in Lima. An independent visibility check confirmed the public worktree marker was guest-visible and the host temporary file was not. Eight real build attempts failed; the model cannot repair this runner environment defect. The failed graph, successful replay and scoped workflow/worker cleanup are retained under `graph-direct-80e11ea62461459fb6e45184702899a5`.

The runner now sets a private per-trial `TMPDIR` under the guest-visible worktree. A new frozen correction trial explicitly references the original failed manifest. It requires terminal failure, successful replay and cleanup, and forbids executing either manifest twice. The expected verdict, source fixture, model settings, budgets, scorer and runtime enforcement remain unchanged. Full workflow success requires a ready environment, actual runsc execution with exit zero, oracle/precondition/sink evidence, persisted API agreement and root/child history replay with external I/O forbidden.

## Current deterministic and packaging evidence

The final canonical suite passes: 2,268 tests passed, 40 skipped, 861 warnings, 71.89 seconds. Skipped service/native cases are not treated as live passes. `just check`, `just generated-check` and `just dev-skills-check` passed. Independent graph-runner regressions pass 23 cases, including unchanged-candidate provenance controls. An installed wheel tested outside the checkout includes the migration, all eleven disabled catalog entries and the corrected Unicode admission implementation. UI source is unchanged; previous frontend checks remain separate evidence.

The optional explicit profile request cap changes full-contract identity only when configured; omitted fields preserve prior serialization. Wire protocol remains `ih-inference-v1`, specification behavior is version 0.2.4. Old allocations and histories are not rebound to the new image or cap. Drain old workers, retain uncertain holds and use a dedicated broker task queue. No automatic direct fallback or rollout is enabled.


The corrected direct graph passed in 232.589 seconds: ready environment, actual runsc oracle, expected verdict, persisted API agreement, Temporal visibility, three production root/child histories replayed without I/O, and scoped workflow/worker cleanup. This is a real complete workflow on the approved local provider rather than a mock or configured-runtime claim. The frozen correction manifest is `graph-direct-tmpdir-manifest.json`; the original failed graph remains retained.


## Native response codec defect

Offline replay of 93 captured real provider response occurrences reproduced the same strict-codec rejection. Pinned PydanticAI 2.49.0 and GenAI pricing data extract OpenAI `completion_tokens_details.reasoning_tokens` into a dynamic `RequestUsage.output_reasoning_tokens` field. The broker allowed only dataclass fields, so legitimate responses were rejected after dispatch. The targeted fix allows this known integer counter, preserves it in both response and subsequent history round trips, verifies result/response agreement, and retains denial of arbitrary extras and negative, boolean, fractional or noninteger counters. Reasoning tokens are already part of completion tokens and are not added to accounting twice. This reproduced cause is consistent with the native post-claim failures; the original requests have no committed result and remain uncertain.


The codec-corrected executor image is `sha256:37f48d86fde77216e1a4841d2c9f83e2829e302cda8f336b1ca5c0bee4e9a910`. Source/context bytes match, and all eleven full-contract policies and actual readiness observations passed again with one lease at a time. All eleven test leases were revoked, and the ledger stayed at the same four retained uncertain requests. The corrected pilot manifest SHA256 is `0b3a839b15d9bfab762f143cdae37efc38605ccc33b3aa9208e0fcfc322bb07a`: 22 fresh native trials only, 37 total agent trials including the original eleven direct and four failed native attempts. It anchors original baseline and failed-report hashes and exact uncertain request identities; neither old report nor old manifest is changed.


The first codec-corrected native pilot was also stopped. Recon committed and recovered two real responses; intake and a later recon request remained uncertain, and the cancelled environment-planner case admitted no request. All three scoped closes passed and the worker was reaped. Six unknown requests are now retained across both pilots. The codec correction therefore enabled real completion but is insufficient to explain the remaining fault. No native Temporal phase has run, and no failed pilot is promoted to acceptance.

The executor now reports only fixed allowlisted diagnostic stage/category markers. Independent review found no secret-bearing interpolation, exception text/class names, request identities, payloads, headers or traceback logging. Cause traversal is bounded and cycle-safe. Provider retries remain zero and ambiguous completion remains terminal. A private one-case investigation captures only these markers before normal owned-container deletion; this diagnostic wrapper is removed before acceptance qualification.


The first stderr-only diagnostic trial retained another uncertain request, bringing the total to seven, with two saved native responses. Missing Docker log markers did not establish an error category. A qualification-only image adds a private mode-0600 file sink to the same fixed executor logger. Before further inference, a zero-call static-marker proof passed: exact native policy/image/process verification, private sink visibility, bounded marker-only capture, unchanged ledger and scoped lease deletion. The failed initial capture proof is also retained; import-based marker emission failed through the sandbox SSH process; the successful route uses standard-library access to the existing private sink. The extra file sink is excluded from production source and acceptance images.


The bounded reproduction sample stopped after its first failed intake case (22.141 seconds); the other two frozen cases were never started. Safe markers identify `provider_request/network` and `inference/network`, before codec or ledger completion. Eight uncertain requests and three saved responses are now retained. Every started scope closed successfully and its worker was reaped. All four approved addresses separately returned HTTP 200 model discovery from the actual guest with verified TLS. These discovery checks do not establish inference reliability.


## Final native diagnostic boundary

The next finite network-detail sample stopped after its first failed case (22.168 seconds); its other two frozen cases never started. Fixed categories identify `remote_protocol`, consistent with the SDK losing the upstream HTTP response. A separate final three-case supervisor sample was frozen at SHA256 `494e9b703991fee701265074450c24269308dc9405c0ae9aafde14285bd4e040`. It also stopped after its first case failed (22.075 seconds), with the other two cases never started. A preparatory launcher failure occurred before imports, dispatch or ledger changes and is retained separately.

Only fixed allowlisted flags were extracted from the exact owned supervisor container before normal revocation. Both container corroboration and log reading passed. The model-specific stale-policy-generation flag was true, alongside `remote_protocol`; framing rejection, response-read failure and upstream-closure flags were false. Negative flags do not prove those other faults absent. The pinned [OpenShell v0.1.2 relay guard](https://github.com/NVIDIA/OpenShell/blob/v0.1.2/crates/openshell-supervisor-network/src/proxy/relay.rs) explicitly closes streams when their policy generation becomes stale. The captured event establishes a native policy-generation closure consistent with this disconnect; the triggering reload or quarantine is not yet established. Policy enforcement is not bypassed or weakened to obtain a passing trial.

Ten uncertain requests and three saved native responses are retained across the finite investigations. Every started scope closed and its owned worker was reaped. No uncertain request was resent or its allocation released. Qualification-only file sinks and diagnostic controller wrappers are excluded from production acceptance. Native live all-agent compatibility remains failed; native live Temporal/full-graph acceptance, deployed-tokenizer attestation and held-out quality remain `not_checked`. All eleven direct live compatibility cases and the corrected direct production graph remain passed. Rollout remains disabled.


## Dedicated qualification cleanup

The final ledger observation retains ten `completion_unknown` requests and three completed
responses. All 38 owned leases are deleted and native sandbox inventory is empty. The exact
owned provider, controller and PostgreSQL containers were removed without deleting volumes;
the production controller factory was restored. An authoritative mode-0600 PostgreSQL dump
is retained privately (SHA256 `9e2701cf7f986058ae71e3cc2edc12a13db9d383c5fb5d9cbe7a1f152f175ca8`).
The original database volume and all frozen manifests/reports remain preserved. The owned
gateway and dedicated guest Docker/containerd helper stopped, with shared firewall state
preserved. All ten primary Compose container identities were unchanged. Cleanup evidence is
retained privately as `live-qualification/cleanup-evidence.json`; this cleanup does not release
uncertain allocations or convert failed native inference into acceptance.


Post-cleanup actual runsc positive/negative execution, PID/memory/resource limits and
build-egress allow/deny/isolation/forced-removal fixtures passed. The primary API, web, S3,
persistence and Temporal visibility smoke passed in verified stub mode, with no real-provider
calls. This does not replace the direct live production graph proof above. Independent dump
inspection joined all ten unknown requests to broker-owned operations in `uncertain` state,
confirming retained budget holds. A preparatory dump attempt against the default socket failed
before shutdown; the explicit dedicated-port dump succeeded and both outcomes are retained.
The previously observed intermittent Docker OOM-notification failure remains a reliability risk;
the current passing fixture does not erase it.
