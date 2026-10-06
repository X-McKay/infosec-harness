# Source quality pass, 2026-10-06

A read-only review of `src/infosec_harness/` and `tests/` (five reports: `agents/` and `tools/`,
`sandbox/`, `workflows/` and `evals/`, the top-level modules, and a cross-cutting pass), then one
fix branch per package, integrated on `claude/quality`. Measured at commit `96ade5f` (the
integration merge of `origin/develop` at `ac89eff`, PR #16); later commits on the branch change
documentation only. The base for every comparison below is `origin/develop` at `ac89eff`.

What this proves: the confirmed defects below are fixed with regression tests whose expectations
come from the documented contract, not from the new code; the deterministic suite, the real local
Temporal tests and the UI checks pass; and the twelve preserved live v11 histories replay on this
code with no native or model dispatch. What it does not prove: anything about the native sandbox
or live inference on this code. The model executor changed, so its image must be rebuilt before
those gates can be checked (see the last section).

## Confirmed defects and their fixes

Each was reproduced or read to a concrete failing input during review, and each fix has a test
that fails on the previous code.

| Defect | Effect before the fix | Fix |
| --- | --- | --- |
| Keep-going classifier truncation | `agent_level` scanned the 500-character report view of each failure link for three substrings, so an `ExecutionUnknown` past the cut, or an inner `TimeoutError`, `RpcError` or `UnsafeSnapshotMetadata`, let `--keep-going` continue after an unknown dispatch or native failure | Classify from the untruncated exception chain with an allowlist of link labels (agent failures, `ModelRetry`, Temporal wrappers); the marker scan stays as a second check |
| Cleanup reserve | The server execution timeout reserved 600 s past the investigation deadline, less than a waited `prepare` plus three cleanup attempts with backoff; a server-ended run never runs its `finally`, leaving owned sandboxes open | `CLEANUP_RESERVE` derived from the named activity bounds (30 min 3 s) is used by `api.execution_timeout` and `cohort.DRAIN`; a timed-out or terminated case records `cleanup: unconfirmed` with the next step |
| Shell wrapper comments and heredocs | The wrapper ran `( $2 )`, so a command ending in a `#` comment or using a heredoc failed with "syntax error: unexpected end of file" and cost a tool call | The subshell closes on its own line; the real wrapper runs under local bash in tests |
| Probe parser accepted arrays | A JSON array of five `[name, bool]` pairs parsed as the full claim set, although the contract requires one JSON object; the parser also feeds finalization admission | The decode hook builds a dict, rejects repeated keys, and requires exactly the five boolean fields |
| File tool output overflow | `read` and `search` could print far more than the 8,192 bytes the worker keeps; one minified file could exceed the native output bound and end the investigation as an unknown execution; failure stderr entered history unbounded | The in-sandbox script cuts lines and stops one byte past the excerpt; failures print one bounded line; the script now runs in tests |
| Provisioning cleanup under repeated cancellation | Owned cleanup awaited `shield(close(...))` once; a second cancellation abandoned it, and `create` could cancel provisioning after `CreateSandbox` crossed the boundary, skipping close | One `_close_owned` awaits close to completion with `process.finish` at all five sites; tests cancel three times during provisioning and during the delete |
| Source verification over-certifying | `verify_source` listed completed operations after a possibly replayed capture, so a command finishing after the capture could be certified `source_verified` | The capture intent records `covered_operations` before dispatch; certification uses only that set; a legacy capture without it certifies nothing |
| Executor ignored unknown fields | A stale executor image silently dropped newer `ModelInvocation` fields such as `timeout_seconds` | Unknown top-level fields are refused, naming them and asking for an image rebuild |
| Bedrock timeouts | The Bedrock client kept botocore's default 60 s timeouts; only OpenAI honoured the request budget | Connect and read timeouts equal `timeout_seconds`, one attempt |
| API error mapping | Every non-404 Temporal RPC error became "Workflow service unavailable" (503), including a running run with no worker | NOT_FOUND 404, INVALID_ARGUMENT 400, DEADLINE_EXCEEDED 504 naming the task queue, others 503 naming the status; each is logged by status only |
| Settings rebinding | `use_settings_file` could rebind after settings were read, so one process could mix environment and file configuration | One process global; binding refuses once settings exist, naming the path |
| Diagnostic exit code | `harness eval --case` always exited 1, even when the diagnostic completed | Exit 0 for a passed gate or a completed diagnostic, 1 for a failed or unchecked gate, 2 for usage or configuration, 3 for operational failures |

The integration also fixed one test defect: `test_inspector_timeout_kills_its_whole_process_group`
used a fixed 0.5 s deadline and read the grandchild's PID file afterwards. Under CPU contention
the deadline fired before the shell published the PID (13 of 16 concurrent runs failed). The test
now expires the real inspection timeout only once the PID file is observed, and publishes the PID
by atomic rename; 16 of 16 then passed under the same contention.

## What changed, per package

- `agents/`: the probe parser contract above; `InvestigationDeps` moved to `agents/deps.py`,
  removing the `agents`/`tools` import cycle; payload-budget errors name the measured size and
  the limit; the duplicate model activity config and an empty retry reason are gone.
- `tools/`: the wrapper and file-tool fixes; build tools run as `./gradlew`, `./mvnw` or a full
  path are recognised; one `evidence_from_result` builds Evidence for both the tool and finalize;
  source changes are caught by type (`SourceChanged`), not by message prefix.
- `sandbox/`: cleanup under repeated cancellation; covered-operation certification; gRPC failures
  classified and sanitised in one place; every failed boundary check is named in its refusal
  (policy, confinement proof, outer fence, transfer bounds); a failed close never replaces the
  original error; typed on-disk receipt records with unchanged keys; the inspector runs through
  the one owned subprocess runner (process-group kill); lifecycle logging with run and operation
  ids, never commands or output; the executor fixes.
- `workflows/`: named activity bounds and `CLEANUP_RESERVE`; one `WorkerIdentityMismatch` and one
  identity capture per worker; one `workflow_runner()` shared by the worker, replay and tests;
  snapshot capture and re-hash off the event loop; replay-safe logging through
  `workflow.logger`/`activity.logger`.
- `evals/`: the classifier fix; `--parallel N` (1 to 8) with a stop latch and a recorded
  limitation; the capacity preflight runs bounded, strict and explained; every qualification
  check is explicit (`not_checked` until run) with provenance and a bounded error; replay starts
  `not_checked`; `evaluate_corpus` split into `_run_case` and `_derive_gates`.
- Top level: `GENERATION`, probe fields and report bounds defined once in `contracts.py`;
  `probe_step` parses with an anchored regex; `definitive_support` returns a named `Support`;
  the API mapping, logging and report reading fixes; the settings and exit-code fixes; one stderr
  log handler (`HARNESS_LOG_LEVEL`); `write_json` refuses NaN and infinity before writing;
  `log_level` and `reports_dir` no longer enter `config_sha256`.

No threshold, label, budget, policy, isolation check or verdict rule was weakened. The OpenAPI
schema changed in two places, both narrowing types the server already produced: the cancel
response is a typed `CancelResult`, and a run summary's `status` is an enum of the lower-cased
Temporal statuses plus `unknown`. `ui/openapi.json` and `ui/src/api/schema.d.ts` are regenerated
and one UI test type follows.

## Size and tests

| Measure | `origin/develop` `ac89eff` | `claude/quality` `96ade5f` | Change |
| --- | --- | --- | --- |
| Python under `src/infosec_harness/` | 4,552 lines | 5,758 lines | +1,206 |
| of which `agents/` / `tools/` | 348 / 358 | 391 / 436 | +43 / +78 |
| of which `workflows/` / `sandbox/` / `evals/` | 731 / 1,405 / 578 | 911 / 1,769 / 881 | +180 / +364 / +303 |
| of which top-level modules | 1,132 | 1,370 | +238 |
| Skill Markdown under `src/` | 6,738 lines | 6,738 lines | 0 |
| Python under `tests/` | 7,247 lines | 9,310 lines | +2,063 |
| Deterministic suite (`-m "not network"`) | 806 passed, 1 deselected | 1,048 passed, 1 deselected | +242 |

The source grew rather than shrank: most added lines are named-check tables that report which
boundary check failed, typed receipt records, bounded error messages, lifecycle logging, and the
`--parallel` scheduler. The deduplications (one generation constant, one workflow runner, one
Evidence constructor, one cleanup helper, one subprocess runner) removed lines.

## Gates

| Gate | Status | Evidence |
| --- | --- | --- |
| Lint (`ruff check src tests scripts deploy/openshell/build_context.py`) | passed | no findings |
| Compile (`compileall src scripts`) | passed | |
| Deterministic and local Temporal tests (`HARNESS_TEST_REQUIRE_TEMPORAL=1`) | passed | 1,048 passed, 1 deselected, three consecutive runs; six concurrent full runs under CPU contention also passed |
| API schema and generated files | passed | `check_api_schema.py`, `generated.py --check` |
| UI (`npm ci`, `check:api`, `npm test`, `npm run build`) | passed | 85 tests; run before the PR #16 merge, which changed no file under `ui/` |
| Zero-dispatch replay of preserved v11 histories | passed | 12 of 12 completed histories from the live cohort `live-eval-v11-17a996360a2b` (1,764 events; 6 `potentially_exploitable`, 6 `likely_not_exploitable`) replay with 0 native and 0 model dispatches, read-only against the live Temporal |
| Native OpenShell qualification (`./dev qualify`) | not_checked | the executor image must be rebuilt from this source first |
| Live inference (`./dev eval`) | not_checked | as above; no model calls were made |
| UI end-to-end (Playwright) | not_checked | not run in this pass |

The replay shows the workflow command sequence is unchanged for v11, so the generation stays
`v11`. Behaviour changes are activity-internal, start options or report fields, and every source
edit changes `code_sha256`, so running v11 workers must drain and restart on this commit as usual.

## Before the native gates can pass

`sandbox/executor.py` changed (unknown-field refusal, Bedrock timeouts), and the tool argv
changed (wrapper, file-tool script), which changes `request_digest`. Rebuild the executor image
as described in `deploy/openshell/README.md`, record its image ID in the model profile, restart
the worker on this commit, then run `./dev qualify` and a cohort. Until then an older executor
image ignores unknown fields and keeps the 60 s Bedrock timeouts.

## Deferred

To v12, because each changes a history payload, an activity argument digest or every worker
fingerprint, which v11 histories and in-flight receipts must keep reading:

- removing `Evidence.timed_out`;
- structured failure `details` on the terminal `ApplicationError`, so clients classify from labels
  rather than message text;
- `WAIT_CANCELLATION_COMPLETED` with heartbeating for native model and tool activities (today the
  `close_run` fence and sandbox deletion end in-flight native work, not Temporal cancellation);
- a typed `Observations` contract, moving harness-owned facts out of `observations`, and an item
  length bound on model-authored evidence id lists;
- the absolute interpreter `/usr/local/bin/python` in tool, model and qualification argv (it is
  part of `request_digest`);
- canonical separators in the worker fingerprint (changing them changes every fingerprint);
- a byte-safe cut of workflow failure links (the 400-character cut is in recorded messages).

Not done in this pass, for other reasons: freezing `Settings` (tests still assign fields; a
separate change with them); per-run receipt subfolders (the layout must keep reading v11 records
until v11 drains); requiring client mTLS for the loopback plaintext gateway and non-empty
`binaries` in workspace egress rules (both need the native semantics confirmed and fixture
changes); refusing a non-loopback `harness api --host` without an explicit flag (an operator
interface decision).
