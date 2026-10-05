# Next session: native capacity and full qualification

Saved October 5, 2026; updated the same evening after `fd4cbb7` (see
[the simplification and tooling record](SIMPLIFICATION_AND_EVAL_TOOLING.md)). Start with this file, `README.md`, `AGENTS.md`,
`dev-skills/harness-change/SKILL.md` and `dev-skills/harness-eval-experiment/SKILL.md`.
This is a continuation plan, not evidence that the planned gateway change is qualified.

## Objective and scope

Continue the simplification to OpenShell + PydanticAI + Temporal, retaining the lightweight
UI. Prefer fewer intentional lines, one investigator using tools and packaged skills,
and native durability/isolation over custom orchestration, persistence or provider brokers.
Backward compatibility is not required. Use Sol 6.1 subagents for useful parallel work;
the user also requested cost-effective delegation.

Inference is authorized only through the self-hosted OpenAI-compatible endpoint
`https://llm.almckay.io/v1`, served model `Qwen3.6-35B-A3B-NVFP4`. No public fallback.
Earlier user-requested Opus/Kubani log investigation is complete; its evidence is adjacent.

## Repository checkpoint

- Branch: `feature/astra-simplification`.
- PR into `develop`: https://github.com/X-McKay/infosec-harness/pull/6.
- Runtime checkpoint: `4164920`, lifecycle-bound confinement proof reuse and native
  operation accounting; committed and pushed. This handoff is a subsequent docs commit.
- Previous corrections: `35d3cb9` fences ambiguous native exit 124;
  `880a733` narrowly reports unsafe generated archive metadata after a known completed
  probe; `9cd4adf` unifies output correction feedback; `c34f1cc` clarifies target reachability.
- Current workflow generation: v11, queue `investigate-v11`, run prefix `investigate-v11-`.
  v10 and older workers must drain. Workflow-breaking changes require another generation.

`4164920` audits confinement once per sandbox lifecycle. Reuse checks native identity,
configuration/spec/revisions, provider readiness and actual container IDs/start times.
Changed, missing or incomplete durable proof closes owned work without repeating an
uncertain audit. The audit request ID is saved before dispatch. Workspace/model sandboxes
remain per investigation; probe sandboxes remain per probe. A fresh adapter reuses the
same proof. Whole metadata comparison still needs real native repetition to establish
that routine activity does not invalidate the binding.

Evaluation now counts local create/audit/exec/capture receipts, including unknown intents
and failed cases. These counts do not prove native ledger occupancy, remote-worker receipt
visibility or a native capacity budget. Legacy repeated audits overwrote proof files, so
historical counts are lower bounds. No new ledger or application persistence was added.

## Why live work is blocked

Pinned OpenShell 0.1.2, commit `6648bd0c290efbc41ba131ee9831ee45cd431f94`, hard-codes
`MAX_ADMISSIONS_PER_CALLER = 1000` in
`crates/openshell-server/src/grpc/mutation_replay.rs`. All retained claims count, not just
unresolved claims. Successful claims are retained for 24 hours; unresolved claims never
expire. Normal admission can prune eligible successful claims. No supported quota override
or manual expiry/reconciliation API exists in this version.

Official stable remained 0.1.2 at inspection. Main commit
`be7af99ff2eacba807d82b69adb0c3d4eaa32158` had byte-identical admission source. An inspected
development release also did not fix the limit. Simply upgrading is not a solution.

Read-only inspection at October 5, 21:35:36 UTC found 1,000 retained claims: 995 completed,
five unresolved, zero invalid payloads and zero expired successes. Earliest successful
expiry is October 6 at 15:56:03 UTC / **11:56:03 AM EDT**; the latest observed success
expires at 21:11:22 UTC / **5:11:22 PM EDT**. Recheck current occupancy before acting.
No future run or automatic follow-up is scheduled.

Historical receipt projection: five completed cases and one failed case used at least
257 operations; completed cases ranged from 28 to 49. Extrapolation to 36 cases suggests
1,097–1,727 operations, retaining observed attempts. This is not a bound or new-candidate
qualification. Unknown dispatches, legacy undercount and unsampled cases prevent treating
it as a guaranteed capacity budget.

## OpenShell change — patch tracked, artifact not built or deployed

The quota patch is implemented and committed as
`deploy/openshell/patches/0001-configurable-mutation-admission-quota.patch` (config key
`openshell.gateway.max_mutation_admissions_per_caller`, default 1000, range 1..=1,000,000;
upstream unit tests passed on Rust 1.97.1). Steps 1 and 2 below are done; steps 3 to 5 remain.
The intended reproducible build: a two-stage Dockerfile on the pinned `rust:1.95.0-bookworm`
image, `cmake` from Debian, the vendored crates and the clone already under
`.harness/openshell/gateway-build/`, `git apply` of the tracked patches, the upstream
`version = "0.0.0"` → `0.1.2` substitution, `GIT_DIR=/nonexistent`, and
`cargo build --release --offline -p openshell-gateway --bin openshell-gateway --features bundled-z3`
through the qualified build-egress builder, publishing the binary and its SHA-256 plus a
provenance record (upstream commit, patch hashes, image digest). Deployment: copy the binary
beside the current one under `/var/lib/ih-openshell/<id>/bin/` (retain the old file), add the
quota key to the guest `gateway-conf/gateway.toml`, run the binary's `config` preflight, stop
the current gateway only after verifying its exe path and command line, start the new one
with the identical arguments and log, then verify `--version`, health and read-only
occupancy. This session was not permitted to author that Dockerfile and build script; the
operator must do or authorise that step.

Increasing a finite quota preserves existing claims and replay protection, unlike deleting
claims. The recommended starting capacity is **10,000 per caller**, to be validated against
actual workload/storage costs. Prefer a small upstream configuration change over a lasting
private fork. A reproducible, tracked patch to the exact pinned source may be necessary
until an upstream release includes it; never silently modify an installed binary.

1. Inspect the pinned native configuration and persistence contracts. Add a validated,
   finite configurable admission quota, preserving the default 1,000. Use the same configured
   value in atomic admission enforcement and bounded expiry scanning. Do not change request
   IDs, caller identity, successful retention, unknown fences or execution concurrency.
2. Test default/custom quota behavior, atomic concurrent admission, successful pruning,
   permanent unresolved claims, duplicate suppression, restart recovery and cleanup bounds.
   Raising the quota must not admit an already-claimed operation again. Measure bounded
   storage and pruning work; 10,000 is a proposal, not a verified safe capacity.
3. Build a reproducible gateway artifact from the exact pinned base plus the tracked patch.
   Record source/patch/artifact hashes and configure this checkout's dedicated gateway.
   Update the relevant tool pins/provisioning documentation; retain SDK/protocol compatibility.
   Preserve the existing database and native caller. Never reset the ledger, rotate callers,
   drop request IDs, accelerate the clock or manually rewrite completion/expiry records.
4. Stop/drain owned workers before replacing their runtime. Deploy only after native safety
   checks pass. Do not alter global tools, host Docker contexts, shared firewall policy or
   another project's gateway. Retain the previous artifact for rollback without deleting data.
5. Verify the configured quota and aggregate occupancy through read-only evidence. Increased
   capacity does not reconcile the five unresolved outcomes, and they must retain fences.
   An upstream reconciliation API is a separate future change requiring native execution
   evidence; do not invent a harness-side substitute.

## Qualification sequence

Operator commands now exist for each step: `./dev qualify`, `./dev eval --case <name>`,
`./dev eval` (owned worker on a fresh queue, `--keep-going` optional) and `./dev replay <id>`;
`--settings FILE` freezes one configuration. Historical evidence under
`live-eval-v11-*` and the five-history offline replay remain the recovery baseline.

1. Freeze and commit a clean candidate; capture worker, runtime, images, model, corpus and
   budget identities. Use a new owned worker queue/configuration for the frozen candidate.
   Never resume unknown model/probe executions from prior failed investigations.
2. Run lint/compile/generated checks and the deterministic suite with pinned Temporal CLI
   1.9.1 and `HARNESS_TEST_REQUIRE_TEMPORAL=1`. Replay preserved native history with model
   and native dispatch disabled.
3. Qualify actual workspace/probe creation, confinement, transfer, receipts and cleanup.
   Qualify repeated model-sandbox reuse through a fresh adapter and actual model turns:
   unchanged lifecycle must reuse one proof, while changed identities/configuration must
   fail closed. The runtime qualifier now checks reuse through a fresh adapter.
4. Run a bounded new investigation of `pathtraversal-fixed`, then representative actual
   investigations, with sufficient native headroom. Preserve failures and unknowns.
5. Run the unchanged full 36-case cohort through ordinary Temporal investigation using
   `harness eval --allow-inference --output <new-file>`. Keep original ground truth, release
   thresholds and budgets. Do not silently resume or replace failed/unstarted cases.
6. Resolve reliable clean-cache Maven builds without weakening policy/TLS/source boundaries.
   Complete affected UI checks. Report each gate as passed, failed, not_checked or justified
   not_applicable. Commit/push progress and update the existing PR. No promotion without
   comparable complete quality and safety evidence.

## Current evidence and remaining gates

- Passed on `4164920`: 279 deterministic tests, one network test deselected, real Temporal
  required; CLI 1.9.1. Lint, compile and generated API/instruction checks passed.
- Passed: preserved native history replay, 169 events, zero native/model dispatches;
  history SHA-256 `162cd6822a564bd0ea93ab0b9173f6e078a568f01f21b2d65968f1901a70bf13`.
- Not checked: new native lifecycle proof reuse and current live correction verification;
  native capacity prevented dispatch. Historical native/UI connectivity evidence does not
  qualify later commits.
- Failed: last full cohort completed five correct cases, failed the sixth, left 30 unstarted.
  Accuracy and unsafe-negative gates remain not_checked. Latest bounded diagnostic hit
  capacity after four successful model responses; owned sandboxes were cleaned up.
- Failed: reliable clean-cache Maven downloads; intermittent native transfer failures persist.
- Not checked: independent held-out quality and Bedrock native integration. Inference scope
  remains self-hosted only. The candidate is not qualified for promotion.

See `QUALIFICATION_STATUS.md`, `NATIVE_ADMISSION_CAPACITY.md`,
`TARGET_REACHABILITY_FEEDBACK.md` and the other adjacent evidence for details.

## Private runtime locations and restart hints

No secrets are copied here. Inspect these private files without printing credentials:

- Native configuration: `.harness/openshell/private/native-config.json`.
- Latest capacity-blocked diagnostic: `.harness/openshell/private/live-eval-v11-263616ced211/`.
- Last full-cohort report: `.harness/openshell/private/live-eval-v11-201cc101da4a/cohort.json`.
- Replay helper: that same full-cohort directory's `replay-first.py`.
- Historical local estimate: `.harness/historical-native-operation-estimate.json`.
- Deterministic log: `.harness/sandbox-reuse-tests.log`.
- Managed Temporal: `127.0.0.1:7439`, namespace `default`.
- Native gateway: `127.0.0.1:49078`; dedicated Lima VM `h`,
  `LIMA_HOME=/Users/al/.cache/ih/1136c19d5a`.
- Native inspection socket: `unix:///var/lib/ih-openshell/1136c19d5a/run/docker.sock`.
  Docker inspection is read-only evidence, never an agent execution route.

All diagnostic/cohort-owned workers and loggers were stopped; check actual service status
on return. Managed services/data were preserved. Do not assume a historical PID identifies
the current gateway. For aggregate inspection, verify the gateway executable and its actual
open database descriptor, then use SQLite `mode=ro` and `query_only=ON`, including WAL.
Query only aggregate counts/timestamps, not raw payloads or credential-bearing configuration.

Use `.venv/bin/` tools and managed runtimes. Any new gateway build/deployment must obtain its
own evidence; this handoff records a proposed implementation, not a completed capacity fix.
