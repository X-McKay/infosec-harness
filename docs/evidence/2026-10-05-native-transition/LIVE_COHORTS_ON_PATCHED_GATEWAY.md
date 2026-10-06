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
| 12 | `f734f3f` | 600k, 40, 300; parallel 3; 82 de-labelled cases | 69 / 67 | 5 | 8 | 0 | First independent accuracy measurement. Failures: three token budgets (`ssrf-fixed`, `perl-sqli-vulnerable`, `javascript-arginjection-fixed`), one backend 502 at the first request (`java-sqli-fixed`), and one harness defect (`c-intoverflow-vulnerable`: a citation of a probe-written file raised `FileNotFoundError` in finalize; non-agent-level, so the stop latch left 8 memory-group cases unstarted). Wrong: `fileinclusion-fixed` (false positive from a probe that altered `sys.path`). Inconclusive: `c-stackoverflow-vulnerable` (no C headers in the image; correct refusal). Two C negatives rest on stand-ins and should be discounted |

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

## Corpus label leak

Runs 1 through 10 used fixtures whose paths and comments carried the label: every pair of the
36-case corpus lived under `eval-corpus/<lang>/<topic>/vulnerable` and `.../fixed`, sources stated
`# VULNERABLE: ...` or `# FIXED: ...` with an explanation of the weakness or the control, the
`unreachable` case's docstring said its sink was not reachable from untrusted input, Java and
JavaScript package names ended in `-vuln` or `-fixed`, and the two findings of each of the eight
Python pairs had different descriptions (the exploitable one describing the weakness). The workflow
withheld `repo_url` from the model's prompt and mounted each snapshot at `/workspace/repo`, so the
directory name was probably not seen, but the source comments, package names and finding
descriptions were available to the agent. The accuracy figures from these runs (142 of 146 through
run 8, 30 of 36 in run 8, 30 of 33 in run 10, 0 unsafe negatives) are therefore not independent
evidence of triage quality; the quality gates were already `not_checked` and stay so. The corpus was
de-labelled on 2026-10-06 in commits `1ab456c`, `4f0d5e6`, `7a8df53` and `f7bc84f` on
`claude/corpus-delabel` (neutral `a`/`b` directories; stripped comments, test names and metadata;
one shared description per pair; a hygiene test), and accuracy must be re-measured on that corpus.

## Promotion, migration and the first de-labelled cohort (2026-10-06, afternoon)

All work merged into develop (#11 API and UI, #12 Java XXE skills, #13 cleanup, #15 UI
polish and Playwright suite, #16 skills coverage and de-labelled corpus, #17 evidence, #18
quality pass, #14 stack simplification) and develop was promoted to main as `f734f3f` (#19).
Live steps on that head, in order:

- Executor image rebuilt from `f734f3f` (`sha256:105b713a…`; the invocation contract now refuses
  unknown fields and Bedrock honours the request budget) and set in the model profile with the
  previous configuration backed up.
- Native qualification passed on that source and configuration (`native-qualification-14.json`
  from a clean worktree at develop's head, `native-qualification-15.json` from a clean detached
  worktree at `f734f3f`; config `68062827…`).
- All 249 retained workflow histories were exported from the compose Temporal with
  `harness export-history` into `.harness/histories/`; the 12 replay histories match their
  replayed `history_sha256` byte for byte.
- Migration from the compose stack per `deploy/README.md`: the old builder removed with its state
  kept, the compose project brought down with all three volumes preserved, the Temporal dev
  server, API and UI started by `./dev` as local processes. The dedicated OpenShell daemon
  refused to stop because its firewall baseline had already drifted earlier in the session
  (compose operations); it kept running throughout, its gateway stayed healthy at quota 40,000,
  and the refusal stands as the documented operator-review signal until the daemon is next
  restarted. `./dev`'s closing qualify step needs `HARNESS_OPENSHELL_CONFIG` to name the private
  configuration; with the frozen settings file it passes.
- Run 11 was a misconfigured launch: the manifest's relative repository paths resolve against
  the checkout running the cohort, while the approved roots named another checkout, so the first
  three cases (parallel 3) were refused by the root check, the stop latch started nothing else,
  and cleanup left 0 containers. The approved root was corrected.
- Run 12 is the first cohort on the de-labelled 82-case corpus, on `f734f3f` from a clean
  detached worktree, with `--parallel 3`, the frozen `settings-82.json` (600k tokens, 40
  requests, 300 s commands), capacity pre-flight passed (29,891 of headroom against 14,760
  required). It is the first independent accuracy measurement; its report is `cohort-12.json`.

### Run 12 in detail

Run 12 (`cohort-12.json`, 13:37 to 15:45 UTC, 2 h 7 min of wall time for 74 attempted cases with
three in flight) is the first run whose accuracy figures are independent evidence: the corpus
had been de-labelled (neutral `a`/`b` directories, no label comments, neutral titles, fixture
tests moved out of the snapshot) and the hygiene test enforces it.

| Measure | Value |
| --- | --- |
| Completed / correct | 69 / 67 (original 36 cases: 33 completed, 33 correct; new 46: 36 completed, 34 correct) |
| Unsafe negatives | 0 |
| Task-success rate as the policy computes it (correct over planned) | 67 / 82 = 0.817, but `complete_corpus` failed, so the quality gates stay `not_checked` |
| Failed | 5: three token budgets, one backend 502, one harness defect |
| Unstarted | 8 (stop latch after the harness defect; run afterwards as `diagnostic-12-remainder.json`) |
| Duration per attempted case | median 243 s, p90 495 s, max 1,685 s |
| Model requests per completed case | median 10, max 28; 8.8 M tokens in total |
| Native operations | 3,034 completed, 0 unknown (41 per attempted case) |
| Capacity pre-flight | passed: 29,891 claims of headroom against 14,760 required |

Findings and their fixes (all in `claude/run12-fixes`, pending at the time of writing):

- **Citation of a probe-written file ends the investigation as a harness error.** Citations are
  validated only in `finalize`, with a strict path resolution that raised `FileNotFoundError` for
  a file the agent had created in the sandbox. Fix: validate citations in the agent's output
  validator with retry feedback naming the path, and make the confinement check raise a typed
  validation error that the keep-going classifier treats as agent-level.
- **Probe that alters the interpreter environment produces a false positive.** On
  `fileinclusion-fixed` the agent's first probe was correct, the verdict rule blocked a positive
  verdict, and the agent then prepended a temp directory to `sys.path`, planted a module named
  like the allow-listed one and superseded the correct probe. Fix: a probe skill rule that a
  probe varies only inputs the sink receives from a caller, never the search path, environment,
  working directory or files the application does not take from the caller.
- **Stand-in oracles pass as negatives.** Both C fixed cases reached `likely_not_exploitable`
  through stand-ins (a hand-written libc stub with `-nostdlib`; a Python reimplementation) because
  the workspace image has gcc but no C headers. The verdicts scored as correct and are discounted
  here. Fix: `libc6-dev` in the workspace image (rebuild and requalify), and a probe skill rule
  that reimplementations, stubs and simulations never carry a definitive label.
- **Budget exhaustions** on three cases (624k, 618k and 629k tokens of 600k): targeted skill
  guidance from their histories; the limits are unchanged.

The eight cases the stop latch left unstarted ran afterwards as `diagnostic-12-remainder.json`
(parallel 3; diagnostics never qualify): six correct (`redos-vulnerable`,
`javascript-zipbomb-vulnerable` and `-fixed`, `toctou-vulnerable` and `-fixed`,
`nullderef-vulnerable`), `redos-fixed` on the token budget (614k), and `nullderef-fixed` called
potentially exploitable. On inspection the investigator was right: the fixed fixture guards the
`address` field but not the parsed document itself, so the payload `null` still reaches a
`None` dereference. The ground truth is being corrected, not the verdict. Across run 12 and this
diagnostic every one of the 82 cases was attempted on `f734f3f`: 76 completed, 73 scored
correct (74 counting the corrected fixture), 6 failed (four token budgets, one backend 502, one
citation defect), one false positive, one inconclusive, 0 unsafe negatives, with the two C
negatives discounted as stand-ins.

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
