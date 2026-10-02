# Credential broker full evaluation — 2026-10-02

Status: **failed** for full-dataset release qualification. All 118 planned cases completed exactly once across all eleven agents; 100 passed and 18 failed. Four agents passed their authored release checks and seven failed. This records successful execution of the evaluation, not successful qualification of the complete harness.

## Frozen scope and implementation identity

- Source: `39d6a4da3fd39ffc8ad49c6419d491e34d9f4007`, reported clean by every agent report.
- Full-dataset frozen plan SHA256: `085c6e04d4af8f9f78a289fbb30981c53fa03d32efa39c5e2df29d334c8101b7`.
- Report directory: `.harness/openshell-spike/live-qualification/full-agent-eval-v2-1790911531`.
- Endpoint: `https://llm.almckay.io/v1`; model: `Qwen3.6-35B-A3B-NVFP4` through native OpenShell brokered production transport.
- Eleven authored datasets; 118 cases; repetition one; concurrency one. Candidate ground truth was never supplied to model requests.
- Intake alone uses the explicitly reviewed `enable_thinking=false`. The other ten agents retain their default thinking settings. Fixed cloned intake routing and exact per-agent contract/profile checks were retained.
- Evaluator version: `deterministic-agent-output-v12`. The v11→v12 change classifies only a trusted closed `BrokerError` with plain-string code `budget` as a failed `budget_exhausted` case so the evaluator can continue remaining cases. Other broker errors still truncate. Closed diagnostics exclude exception text and provider bodies.
- This change affects evaluation outcome/provenance only. Agent runtime contracts, transport retries, Temporal behavior, output expectations, execution guards, price ceilings, and admission budgets were unchanged. No threshold or expected label was weakened.
- Verified retained deterministic validation for this source: **2,586 passed, 40 skipped**, in `full-eval-v2-final-checks.log` (SHA256 `5bd46796270aef4514b0c435264c506679e2e2ce455a910358a421bcc29dc680`). Its source39d linkage is hash-pinned in `native-v5-rerun-reviewed-cause-evidence.json`, verified by the V2 semantic proof below. Skips are not evidence of live qualification.

The earlier full run truncated at an intake budget error before the evaluator classification repair. Its reports, request records, and failure remain retained. V2 is a separately frozen fresh run with new run/invocation identities; it did not resend old request identities or reclaim existing uncertain holds. The protected pre-V2 ledger baseline was 346 rows (15 completion-unknown holds and 331 completed requests). Prior one-case diagnostics and historical holds remain protected.

## Agent results

The passing-case count below is derived from the frozen planned case count less the report's failure categories. It is not rounded from task-success percentages. Release checks use each unchanged authored policy; consequently context and probe-planner can pass their release threshold while retaining one semantic mismatch each.

| Agent | Cases | Passed | Budget stops | Wrong answers | Invalid output | Release | Failed release checks |
| --- | ---: | ---: | ---: | ---: | ---: | --- | --- |
| build-repair | 14 | 12 | 1 | 1 | 0 | failed | budget_exhausted_count |
| context | 15 | 14 | 0 | 1 | 0 | passed | none |
| env-planner | 10 | 9 | 0 | 0 | 1 | failed | schema_validity_rate |
| intake | 9 | 8 | 1 | 0 | 0 | failed | budget_exhausted_count |
| partial-build | 9 | 4 | 5 | 0 | 0 | failed | budget_exhausted_count, task_success_rate |
| probe-author | 10 | 10 | 0 | 0 | 0 | passed | none |
| probe-diagnosis | 13 | 11 | 0 | 1 | 1 | failed | schema_validity_rate |
| probe-planner | 10 | 9 | 0 | 1 | 0 | passed | none |
| probe-repair | 10 | 10 | 0 | 0 | 0 | passed | none |
| recon | 9 | 5 | 0 | 4 | 0 | failed | task_success_rate |
| verdict | 9 | 8 | 0 | 0 | 1 | failed | schema_validity_rate |
| **Total** | **118** | **100** | **7** | **8** | **3** | **4 passed / 7 failed** | |

## Failure classification and independent evidence

### Seven budget stops

- Build-repair (one): a completed response spent 15,593 reasoning tokens, then returned a read-files tool call. After appending that response, even removing all function schemas and emptying all prior tool results leaves a 113,985-unit next-input reservation above the 100,000 operator bound. This is input admission, not a timeout, SDK request-count exhaustion, or provider overrun.
- Intake (one): a reversed vulnerability-class source range was repaired; two later proposals repeated unsupported positive symbol evidence. All proposals parsed as AtomicFinding. With thinking disabled and zero reasoning tokens, the final response alone gives a next-input lower bound of 22,035 above 20,000; reconstructed static feedback gives 22,456. The fourth request was not dispatched. The same SQL case passed an earlier one-case diagnostic; the current failure is retained as stochastic evidence.
- Partial-build (five): repeated structured tool-call bursts enlarge the next input. Four cases have unconditional lower bounds above 100,000 even after removing function schemas and all prior tool-return contents: 161,561; 158,451; 149,554; and 201,426. These bursts include output-length responses, numerous repeated final-result/function calls, and relatively few reasoning tokens. They must not be described as reasoning-only failures.
- The remaining partial-build case has a reduced response-only bound of 64,979, below 100,000. Retained function schemas plus empty tool-response envelopes yield 108,477, but actual fresh returns and compaction are not persisted. The exact exhausted cap remains **not_checked** independently; the observed disposition remains the closed broker budget error. Four dispatched requests are below the 16-request allowance and allocated tokens are below the cumulative reservation. Do not promote the conditional envelope calculation to an unconditional cap proof.

Every retained request for these investigated failures is completed with no provider overrun. Conservative invocation bookkeeping can remain uncertain/revoked without indicating a new provider completion-unknown request. Rejected next requests are not persisted; reconstructed bounds are offline evidence, not captured rejected wires.

### Eight wrong answers

- Build-repair (one): V2 case `cpanm-that-installed-nowhere-perl-looks` returned a schema-valid `perl:5.40` plan with `gcc`, `make`, and `libc6-dev`, no install commands, and empty environment. Its frozen predicate requires `--local-lib` in packages or install commands; neither contains it, so the independently reproduced prediction is `unaddressed` vs expected `addressed`. Ten native requests completed, no output retries/overruns. Retained diagnostic sandbox commands inspected Perl/cpanm paths and attempted dependency resolution, but do not establish that the final plan imports DBD::SQLite. This is exact V2 experiment `exp-36bd874dd7566cc0`, independently retained; older CPAN evidence was not substituted.
- Context (one): the model acknowledged that a private SQL helper's only repository caller passes a constant, but assumed external production exposure and returned reachable rather than unreachable. This is false-positive reachability, not a falsely safe early exit.
- Probe-diagnosis (one): generic import failure for an undeclared module was classified as an environment dependency issue rather than probe defect, despite no evidence that the module should have been installed. This routes repair incorrectly; it did not claim a valid negative.
- Probe-planner (one): chose a filesystem canary for an in-process deserialization gadget where the contract explicitly prefers marker output when both a canary and a local flag work. The canary may detect execution; this is oracle-selection nonconformance, not proof of sandbox escape or an impossible payload.
- Recon (four): accurately identified the ecosystem but emitted decorated free-form labels. Two Java labels include version17; one Test::More label includes explanatory prose; one JavaScript/Node and Jest label includes qualifiers and package-script commentary. Schema accepts these strings, whereas the unchanged scorer lowercases the language and full-matches one canonical framework label. These are label-format mismatches, not evidence that Java/JUnit, Perl/Test::More, or JavaScript/Jest was misidentified.

### Three invalid outputs

- Env-planner (one): all eight proposed EnvironmentSpecs parse successfully. Early proposals omit several Maven runtime requirements. Later proposals retain a path-valued JVM selector and no real Surefire provider warmup. The final proposal fixes the selector, but install commands only compile and do not execute a JUnit warmup test. Semantic validator retries exhaust without accepted output. This is **semantic guard failure**, not Pydantic schema parsing failure.
- Probe-diagnosis (one): completed reasoning-only response at 16,000 output tokens, all counted as reasoning, length finish, no typed result or output retry. Frozen positive execution facts support valid-positive, but no diagnosis was emitted.
- Verdict (one): completed reasoning-only response at 16,000 output tokens, all reasoning, length finish, no typed result or output retry. The fixture's claimed negative conflicts with false precondition/return markers; inconclusive is supported. No unevidenced safe verdict was accepted.

Provider completion and evaluator success are separate: a known completed response can still yield no accepted agent output. No controlled direct-provider baseline was run, so these semantic, formatting, and output-limit failures do not establish an OpenShell broker regression.

## Execution and recovery boundaries

- Full authored evaluation completion: **passed**, all 118 cases, no automatic per-case reruns.
- Full agent release qualification: **failed**, four agents passed and seven failed.
- Authored build-repair execution-check case `perl-dbi-driver-not-installed`: **passed**, controller check `perl_dbd_sqlite_v1`, secure-sandbox-v1. Build exit0 (4.000s), dependency check exit0 (0.917s), no timeout; source hash `c98b12eab66098caaff6ab764b6c1e252f7d0c3d4656f13535024023bb6e63c0`. Execution success overrides the coarse mention predicate for this case: `--installdeps` can fetch the needed module without spelling its name in a command. This is narrower than executing every proposed build plan.
- Other planner/profile/diagnosis/verdict fixtures: actual model calls and retained tool flow are evidenced, including diagnostic sandbox commands where returned. Their presence does not prove the final proposed build or exploit succeeds; actual proposed payload/build/probe execution is **not_checked** unless the case explicitly carries an execution check. Recorded probe-execution facts are fixture inputs, not newly executed probes.
- Full live durable-history replay: **not_checked** by these local evaluation runs. Earlier synthetic real-Temporal replay evidence for the intake feedback patch remains separate and must not be described as production historical replay.
- Each aggregate ledger check reports the protected 15 unknown holds unchanged. The final aggregate observed 759 rows, implying 413 new rows relative to the 346-row baseline. Independent post-full SQL/request-union preservation passed, with all 413 new requests explicitly linked to runtime evidence. The separate final checkpoint after native qualification is recorded below.
- The evaluator-only classification fix changes no durable workflow commands or transport. Recovery continues to retain saved completions and old unknown holds; it does not resend unknown requests. Prior outcomes and experiment identities remain retained.

## Native qualification and graph

| Gate | Status | Evidence |
| --- | --- | --- |
| Eleven LocalOps native qualification cases | failed: 10/11 execution and semantic passed | local report SHA256 `7b341d9157c796194160a88186b9eefea93ba37b591b37c52f24f31534597bf6` |
| Eleven Temporal native qualification cases | failed: 10/11 execution, 9/11 semantic passed | Temporal report SHA256 `7e866e536da7e2f2c4c3cb0d8056881ea6f1e7d507186da5184f55bbf007c09d` |
| All 22 native qualification cases | failed: 19/22 semantic passed; two budget failures, one wrong answer | terminal report SHA256 `2a34f0f896900bfcc2d7a14e94907a0701b79b27062157653c2e70ae458876f5` |
| Owned Temporal history replay | passed: all 11; zero fresh provider calls | final summary SHA256 `f525de0b0e3c9efd6549089ef3cfd7641de2165d5606d9c1005209bde7ab5698` |
| Case and Temporal worker cleanup | passed: all 22 case cleanups and Temporal worker | frozen owned reports and independent final retention seal passed |
| End-to-end graph | not_checked; full-release and native prerequisites failed | withheld under frozen gate |

These are eleven frozen cases per phase, not full-dataset release thresholds. Local intake failed a budget guard; Temporal partial-build failed a budget guard; Temporal build-repair completed and replayed but returned a plan that omits the frozen libpq prerequisite. All other native case semantic outcomes passed. Intake has different stochastic outcomes across phases: Local failed while Temporal passed; neither outcome replaces the other.

The current native frozen manifest is source `39d6a4da3fd39ffc8ad49c6419d491e34d9f4007`, SHA256 `f317728ffbeef1c64f1743fdd1b90e998479ddf54787128a7846a8f671961b4a`. The report's manifest digest, both 11-case reports, all 22 cleanup results, all 11 unique history files/event counts, and source identity were verified without new model, replay, or database calls. The replay fixture replaces both provider request and invocation admission methods with forbidden handlers and verifies ledger equality before/after each replay; the eleven actual saved histories passed with zero fresh provider calls. This is actual current-history replay, distinct from synthetic replay and from actual sandbox execution of every proposed final build or probe. Diagnostic sandbox commands and the separate controller dependency build check have their narrower execution evidence stated above.

Current native failures:

- Local intake: exact current root `6bb60e6f3c14e40c859dfce03b4530365389bba8cbc9cf9678e4402dfb7e219f`; three schema-valid completed outputs, repaired source range followed by repeated unsupported symbol support. Thinking false, reasoning zero; next-input response-only lower bound21,999 exceeds20,000. Local cleanup passed. This is separate from the earlier full-dataset SQL failure.
- Temporal partial-build: exact owned workflow history records a nonretryable BrokerError budget activity failure. Its saved scheduled next model activity retains messages/settings/parameters; offline pinned codec/provider shaping gives conservative input reservation255,625 above100,000. Last completed response hit16,000 output with57 final-result calls and709 reasoning tokens. Five request completions known; cleanup and actual history replay passed. The computed input is pre-transport activity input, not a captured rejected HTTP wire.
- Temporal build-repair: missing-system-library expected addressed but accepted empty package/install lists predict unaddressed under the unchanged libpq predicate. Five requests completed without overrun/retry, workflow execution/cleanup/history replay passed. A successful workflow does not establish successful building of this proposed environment.

## Final retention and remaining gates

Independent terminal preservation is **passed**. The dedicated database contains 837 requests: 822 completed and the original 15 completion-unknown held requests. All 491 new requests match the exact report union: 413 from the full V2 evaluation and 78 from native qualification. No new completion-unknown, accepted or dispatch-intent records remain. An independent dump comparison preserved every existing request and budget record column against both the 346-record pre-V2 and 759-record post-full checkpoints, including full budget states and timestamps. No old hold was released or rebound.

All 347 owned leases were deleted and native sandbox inventory was empty. Both provider identities, all ten primary service container identities, executor/supervisor images, evaluated source and configuration remained unchanged. Dedicated infrastructure remains running; no state reset or production rollout occurred. Private database dumps, credentials, PKI, request payloads and raw logs remain ignored under `.harness/`.

- Final evidence seal: `full-eval-v5-rerun-final-evidence-seal.json`, SHA256 `667beac3be8c8569df0c981a4ad24f35ccdf7ea77148f120a89346a7bb935981`.
- Independent terminal dump: SHA256 `b44be5ef402fd0778e4d450299d85ef89ae66c910d578a8acb0171fee72838ba`.
- Terminal retention proof: SHA256 `2fd81b46fbf7baa3d00a3ce11cdaaa03b19bdd2a6eff293c1587cbedae52222c`.
- Entire-record preservation against both checkpoints: SHA256 `8823e9c37e47e6013584eb7259796f78e9282bc5031fdef3b4bd793c975b7849`.
- Graph retirement proof: SHA256 `653908106443a2c3dd0462b81b530e592c795f7ca90f65ce62435db240fc0674`; its exclusive claim was exercised and further execution blocked. Graph remains **not_checked** because both prerequisite qualification gates failed.

Canonical lint/compile/agent checks, generated and development-skill drift checks, the deterministic suite and all six CI checks passed on the evaluated code. Local UI checks are **not_applicable** to these evaluator/test-support changes; CI web checks passed. Hosted Temporal/database and Kubernetes deployment, workload identity, deployed tokenizer/weights attestation, held-out population quality, server grammar enforcement, and future Credential Driver/Content Inspection implementations remain **not_checked**. State/data migration is **not_applicable** to the requested scope. The endpoint accepts unauthenticated requests, so these trials do not establish upstream credential enforcement. No controlled direct-provider comparison establishes these failures as broker regressions.

The final publication commit changes documentation only; model, evaluator and runtime bytes remain those of the pinned tested commit. Full release and native qualification remain **failed**. Successful completion, cleanup and replay do not override those failures.

## Follow-up work for a separately reviewed experiment

These are future investigation targets, not implemented changes or authorization to alter the current frozen run:

1. Bound parallel function/output tool-call shaping and repeated provider output before large responses multiply admission envelopes. Preserve fail-closed behavior, typed codec restrictions, token ceilings, request identities, and historical compatibility; add independently justified burst regressions.
2. Review per-agent reasoning profiles using observed reasoning-only failures and genuine reasoning cost. Compare bounded non-thinking/limited-reasoning candidates under fresh identities and fixed expectations; do not infer that disabling reasoning fixes semantic errors.
3. Add model-facing canonical language/framework fields or strict typed labels while preserving necessary version/context metadata separately. Do not broaden the scorer to fish framework names from arbitrary prose merely to turn these failures into passes.
4. Improve bounded trusted-field semantic repair feedback for unsupported intake symbol evidence and Maven warmup prerequisites. Keep evidence acceptance, source guards, static trusted diagnostics, and historical retry-text compatibility intact.

## Immutable report hashes

| File | SHA256 |
| --- | --- |
| `build-repair.json` | `392ddaf7a664e354ff2a8164146e74a3d722c33b1d94c74eec8aef4474b4306b` |
| `context.json` | `470f4cccdcd528bb085378e34a28ac6c0f00d65be418346bca436cf961f9f56b` |
| `env-planner.json` | `ddf3eb1c6ee9b033cc5481129e50137f84815668c4e376f49aaefa3e8dcd8419` |
| `intake.json` | `d6999040b982616ca0ebe223326c6d580bf32f01941a05de2ad9aff56f65f10e` |
| `partial-build.json` | `8e3b7f161c41ac38863f9ed2c525d857332487af575ef4f4ef07e7a3edefdbe7` |
| `probe-author.json` | `b37b6590e9519d7a00ec9a22f6365cfb4fb85a7a9083dc1b6c6b4004933098e3` |
| `probe-diagnosis.json` | `b84262276035dd6f36bf7aa34ea6f052dbcc48838ad83f5a7a7d02c2e4eea9dc` |
| `probe-planner.json` | `1c2bde2e3b14b7799e083853100dee79652c8767a33f417b4a393c31480fb20c` |
| `probe-repair.json` | `025ebd6ff7365460f3fc5ffcbf5f6328fa36b0dc0c2c518ebe0386399456aed7` |
| `recon.json` | `03dd11c91bc32a697105e1632e0cf06022ffdd795fe439822d49e8dbc9f2e1df` |
| `verdict.json` | `3883b4685bf8d1b16e9660b775b1d015bab707f154aca58c981c83833d81c010` |

## Private diagnostic index

The following immutable files reside beside the reports. Clarifications supersede only the stated summary phrasing; original evidence files remain unchanged.

| File | SHA256 |
| --- | --- |
| `readonly-build-repair-budget-stop-analysis.json` | `3d4f92213a0d663e4132bebb0af39d067f34b0beefb76e7d5737903e358a5702` |
| `readonly-context-constant-caller-mismatch-analysis.json` | `b77ea10239a90571cc196af901e32f89f6cd18dbc2100538d176cec4ee98be6f` |
| `readonly-env-planner-invalid-output-analysis-clarification.json` | `b058ba4baf0eab45d7c6a70f95d3d23096404bf987fdd3b6a88fab824d31e75d` |
| `readonly-env-planner-invalid-output-analysis.json` | `966c7494223f4e5982f45893e512fd6df81c57ed65dfaacdd5273a2757a08a83` |
| `readonly-intake-budget-analysis-final-summary.json` | `6ef4776635c1ad186d0f48b7743a8a81a8f6b6e848185168e93d327d28cccdf2` |
| `readonly-intake-budget-analysis.json` | `a99bf2c6d9a5967a0f3d194c7e81c264416ed17385971ebd80210f55b6755d40` |
| `readonly-partial-build-failure-analysis.json` | `eb4ba23d76d6f2496d558b4cb8076547d19006c46e2e08df5c433aa80b7738d9` |
| `readonly-partial-build-failure-final-summary.json` | `9a62368e04dbdb55068e386d64d5ba01629b0121241e4bcc6c234f9a92fd1079` |
| `readonly-partial-build-failure-response-supplement.json` | `a1f6df13dbace21b4e99b633ee012ed96faa611198ec1cea8cb6ba63cd122f39` |
| `readonly-partial-build-fifth-budget-analysis.json` | `43d2a33b1e25fe0137755a6185ecfe2009bb507d7b5c76273b8b460a1c0f1a7f` |
| `readonly-partial-build-fourth-budget-analysis.json` | `f3522b985d50839b5c44ab9f0b77788da6daf1589a4919b65818516bf681f69a` |
| `readonly-partial-build-second-budget-analysis.json` | `a1092c53b1f6b802690955fc3daa126be66498171acae4881918cb9943886c9a` |
| `readonly-partial-build-third-budget-analysis.json` | `ed129db068c403d30f49b8d3a766246351bc7dae2cf4a0c37cb914b1f614338e` |
| `readonly-probe-diagnosis-failures-analysis.json` | `8aacb3b136c3b2dd7e5979db67c2850b39ccb555fadc648c58d7ded2f671adcf` |
| `readonly-probe-planner-failures-analysis.json` | `74f7262aa0b84ace1a996c37726585dd20b641a2e252aaa42943fe96877be3a3` |
| `readonly-probe-planner-failures-source-supplement.json` | `41fb2b8fd4990540f5d87087195d22c0644085b26c72fe6284f581c56b3a4355` |
| `readonly-recon-failures-analysis.json` | `05ac62e49d5ca60c6b487006fd25c86bf0867fb2b952d2f7ec8ff41ed11d10cd` |
| `readonly-verdict-failures-analysis.json` | `699da25d5e2a72b1ab4fab5800bbe4d86ff568be1363dccfe2f9887d9882dd9c` |

## Current native private evidence hashes

| File | SHA256 |
| --- | --- |
| `report.json` | `2a34f0f896900bfcc2d7a14e94907a0701b79b27062157653c2e70ae458876f5` |
| `local.json` | `7b341d9157c796194160a88186b9eefea93ba37b591b37c52f24f31534597bf6` |
| `temporal.json` | `7e866e536da7e2f2c4c3cb0d8056881ea6f1e7d507186da5184f55bbf007c09d` |
| `manifest.json` | `f317728ffbeef1c64f1743fdd1b90e998479ddf54787128a7846a8f671961b4a` |
| `readonly-native-v5-local-intake-analysis.json` | `0d73451d89fec9e6356c7161459e50b401b13e17e1657bda37fe76d067fc2fc0` |
| `readonly-native-v5-temporal-buildrepair-analysis.json` | `0789ed7f1447d6afd911208d5f45b991b6e31946a91f4c00fde12c17a11ab8ac` |
| `readonly-native-v5-temporal-partialbuild-analysis.json` | `ccc5acf5c0e02c9d9c85070c3e6b603f316d9fe70b1b1b562f231fbfbdbcce18` |
| `readonly-native-v5-temporal-terminal-summary.json` | `8b9a38a4e7cce1c65d22266baf6dc761f8d58177ef081466762e128fbe5a76c8` |
| `readonly-native-v5-final-failures-summary.json` | `f525de0b0e3c9efd6549089ef3cfd7641de2165d5606d9c1005209bde7ab5698` |
