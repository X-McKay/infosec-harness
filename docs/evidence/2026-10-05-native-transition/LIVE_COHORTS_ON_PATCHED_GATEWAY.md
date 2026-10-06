# Live cohorts on the patched gateway — 2026-10-05/06

Branch `claude/native-transition-e2e-eval-f4ee3f`. Private evidence for every run below is in
`.harness/openshell/private/live-eval-v11-17a996360a2b/` (frozen `settings.json`, each
`cohort-N.json` and `cohort-N.log`, qualification reports, and the diagnostics named here).
Ground truth, the 36-case corpus, the release thresholds (75 percent success, zero unsafe
negatives) and the probe admission rule's evidence requirements were not changed. Operator
budgets were raised between runs 5 and 6 and again before run 7; each report records its limits.

## Runtime deployment

The patched gateway (`deploy/openshell/patches/0001-configurable-mutation-admission-quota.patch`)
was built reproducibly with `deploy/openshell/build_gateway.sh` on `rust:1.95.0-trixie`
(bookworm's GCC 12 lacks the C++20 `<format>` header Z3 5.1.0 needs) and rolled out with
`scripts/openshell_gateway.py`: binary SHA-256 `e334d59c…a703`, installed beside the pinned
release binary, `max_mutation_admissions_per_caller = 10000`, config backup retained. Read-only
inspection afterwards showed the same 1,000 retained claims and a healthy gateway; the ledger
was never modified. On 2026-10-06 09:56 UTC, with no live workloads, the same helper raised the
quota to 20,000 (`gateway.toml.before-20261006T095650Z` retained, verified process swap,
healthy). `scripts/openshell_admissions.py` then read 8,344 retained claims through the
verified gateway process in SQLite read-only mode. Commit `590128f` makes that reading a
pre-flight: `harness eval` records it as the report's `native_operation_budget` and refuses to
start when headroom is below `cases × (max_requests + max_tool_calls + 40)`; the live check
before run 10 passed with 11,656 claims of headroom against 6,480 required.

## Runs

| Run | Candidate | Limits (tokens, requests, command s) | Completed / correct | Failed | Unstarted | Unsafe neg. | Stop cause |
| --- | --- | --- | ---: | ---: | ---: | ---: | --- |
| 1 | `1f33e7e` | 300k, 30, 120 | 12 / 12 | 1 | 23 | 0 | DNS `ConnectError` inside the model sandbox; flattened to an opaque `ActivityError` |
| 2 | `1fbeeda` | 300k, 30, 120 | 6 / 6 | 1 | 29 | 0 | Output corrections exhausted; classifier saw the inner `ModelRetry` type |
| 3 | `d1838b2` | 300k, 30, 120 | 17 / 15 | 2 | 17 | 0 | 2.6 MB Java workspace restore exceeded the gateway's 1 MiB gRPC message limit |
| 4 | `cf73d92` | 300k, 30, 120 | 11 / 11 | 1 | 24 | 0 | Agent overwrote original source; the integrity refusal failed the investigation |
| 5 | `9b27b60` | 300k, 30, 120 | 26 / 25 | 7 | 3 | 0 | Slow `npm install` hit the gateway's ambiguous exit 124; six token-budget failures |
| 6 | `4edf1c6` | 600k, 40, 120 | 25 / 25 | 2 | 9 | 0 | Exit 124 again: a killed child kept the exec pipes open |
| 7 | `67ab5bc` | 600k, 40, 300 | 19 / 18 | 5 | 12 | 0 | Four provider `Request timed out` failures (5 s connect default) during an endpoint slowdown; then the operator edited source during the run and the identity guard refused, as designed |
| 8 | `f7a751e` | 600k, 40, 300 | 30 / 30 | 6 | 0 | 0 | First run to attempt every case. Four external 502 `upstream_unreachable` from the inference backend; two token-budget exhaustions (`java-sqli-fixed` never applied the Maven recipe; `perl-sqli-vulnerable` printed observation values as 1/0, which the parser rejects) |
| 9 | `32610fe` | 600k, 40, 300 | 0 / 0 | 13 | 23 | 0 | Inference backend returned 503 `no available server` from the first case; stopped by the operator after 13 agent-level failures (`ModelExecutorError`), cleanup confirmed: 0 containers, 0 unknown operations |
| 10 | `590128f` | 600k, 40, 300 | 33 / 30 | 3 | 2 | 0 | Operator error: the launching shell had a 2 h limit and was killed with case 34 in flight; the drain worker on the recorded queue let the orphaned tool activity time out, the workflow failed closed without retrying, and cleanup left 0 containers. Failures: `java-xxe-vulnerable` and `java-xxe-fixed` on the token budget (a broken nonce oracle, since fixed in the skills), `javascript-cmdi-fixed` on a backend connection error at the first request |

Totals: 146 completed investigations, 142 correct, 0 unsafe negatives. Every completed
`likely_not_exploitable` case was correct except `testonly` twice (before reachability guidance)
and `ssrf-fixed` once (a resolver-patching DNS-rebinding argument). Run 8, on the rebuilt
workspace (Perl `DBI`) and executor (request timeout) images, completed 30 of 36 with every
verdict correct: an observed 83.3 percent success rate against the 75 percent threshold, but
`complete_corpus` failed on the six failures, so the quality gates remain `not_checked`.
Typical cases cost 7 to 14 model requests and 25 to 45 native operations; measured wall time
in run 8 was a median of 2.2 minutes per case (1.2 to 4.6). Read-only inspection after run 7
showed 6,385 retained claims; run 8 added 1,670, keeping the session near 7,100 of the
10,000-claim quota.

## Defects found live and their fixes

| Observation | Fix | Verification |
| --- | --- | --- |
| Second sandbox of each run failed fresh-adapter reuse: `metadata.resource_version` advanced 9→10 after one exec | Exclude the counter from the lifecycle binding (`449b575`) | `harness qualify` passed; tests updated with the corrected expectation |
| `outer.fence_digest` flipped for one running container: `docker inspect` returns `Mounts` in varying order | Digest an order-canonical view; name changed paths in the error (`1f33e7e`) | 90 s native observation diagnostic; qualify passed |
| Workflow flattened failures to `ActivityError`; keep-going could not classify | Carry the outermost meaningful type and a typed message chain (`1fbeeda`, `d1838b2`) | Deterministic tests; live classification in runs 3 to 7 |
| Executor exit on a sandbox DNS failure ended the cohort | `ModelExecutorError` is terminal and keep-going continues (`1fbeeda`) | Live run 3 continued past such failures |
| Contrary early probe vetoed every later correct verdict (`unreachable`) | `superseded_evidence_ids`: older flawed probes may be disowned by a newer cited one; report keeps them (`cf73d92`) | `unreachable` correct on all later runs; tests |
| 2.6 MB restore exceeded the 1 MiB gateway message limit | Deliver archives in parts under 900 kB, each a replayable receipt (`cf73d92`) | Deterministic tests; Java cases completed in runs 5 to 7 |
| Original-source change made `run_probe` fail the investigation | Refusal returns bounded feedback naming the file; refused probes cannot be cited (`9b27b60`) | `deserialization-fixed` correct in runs 5 to 7 |
| Gateway's ambiguous exit 124 on slow commands | In-sandbox `timeout -s KILL` wrapper (`4edf1c6`), then file-captured output so lingering children cannot hold the stream (`67ab5bc`) | Native measurements: 137 at the budget with background and `setsid` children; quotes and probe line preserved |
| Six budget exhaustions in run 5; Perl `cpanm` thrash; Java `user.home = ?` | Budgets 600k/40/300 s; environment skill rows for Perl and Java; investigate skill reachability rule | `ssrf-fixed`, `java-xxe-vulnerable`, `testonly` passed in run 6 |
| Four `Request timed out` executor exits during an endpoint slowdown | Invocation carries the kill budget; executor applies it as the whole-request timeout (`6f3bc4e`) | Deterministic tests; executor image rebuilt |
| `cpanm` cannot reach an index under the workspace policy | `libdbi-perl`, `libdbd-sqlite3-perl` in the workspace image (`6f3bc4e`) | Image rebuild and requalification before run 8 |

## Gates after run 7

| Gate | Status | Evidence |
| --- | --- | --- |
| Deterministic suite | passed | 297 passed with `HARNESS_TEST_REQUIRE_TEMPORAL=1` on `6f3bc4e` |
| Preserved v11 history replay | passed | Five histories, zero dispatches, on every candidate |
| Native workspace/probe lifecycle, reuse, cleanup | passed | `harness qualify` on every candidate since `449b575` |
| Patched gateway deployment | passed | Hash-verified install, preflight, verified process swap, health, quota 10,000 |
| Repeated model-sandbox reuse through a fresh adapter | passed | Live runs reuse one proof per sandbox across 7 to 34 model turns |
| Full 36-case cohort | failed | Run 8 attempted all 36 and completed 30; six failures (four external 502s, two budgets) |
| Task-success threshold, unsafe negatives | not_checked | No complete cohort yet; observed 142 of 146 correct and 30 of 36 in run 8, 0 unsafe negatives |
| Reliable clean-cache Maven build | not_checked | Java cases pass when the endpoint is responsive; the Maven recipe is in the environment skill |
| Bedrock native provider | not_checked | Out of scope |

A diagnostic rerun of the four 502 cases on `5656793` (`rerun-502.json`; diagnostics never
qualify) completed all four correctly: `deserialization-fixed` 18 requests, `javascript-cmdi-fixed`
6, `perl-xss-vulnerable` 13, `perl-xss-fixed` 12, between 134 and 188 seconds each. Across run 8
and this rerun, 34 of the 36 corpus cases have a correct verdict on this candidate family; the
two remaining failures were budget exhaustions whose causes (Java recipe adherence, Perl boolean
encoding) are now addressed in skills and tool feedback but not yet observed live.

Run 9 was the restructured candidate (`agents/`, `tools/`, `workflows/`, `sandbox/`, `evals/`,
`skills/`), qualified before the run; its 13 failures were all the backend's 503 surfaced as
`ModelExecutorError` and say nothing about the candidate. A recovery monitor polled a minimal
completion every 60 s; the backend answered 200 again at 09:56 UTC.

Run 10 on `590128f` was the first run with no runtime stop cause of its own: every failure was
either the agent's probe engineering (two Java XXE cases, root-caused to a nonce mismatch in the
agent's oracle and fixed in the skills) or the external backend. It was cut short by the operator's
launcher after 33 of 36 cases, so `complete_corpus` failed again and the quality gates stay
`not_checked`; observed accuracy was 30 of 33 with 0 unsafe negatives. The three unfinished cases
ran afterwards as a diagnostic (`diagnostic-10-remainder.json`; diagnostics never qualify) and
were all correct: `javascript-xssesm-fixed` (594 s, 20 requests), `perl-xss-vulnerable` (150 s,
13), `perl-xss-fixed` (211 s, 12). Across run 10 and the diagnostic every case was attempted on
`590128f`: 33 correct, 3 failed, 0 unsafe negatives. The quota was then raised to 40,000 for the
82-case corpus (pre-flight needs 14,760 claims of headroom at the conservative ceiling).

Next: a full cohort on the consolidated candidate (develop with the quality fixes and the expanded
corpus), launched detached from any tool time limit, after requalification.
