# Native admission capacity — 2026-10-05

The bounded diagnostic on `880a733` stopped during model sandbox confinement verification,
before that turn's inference dispatch. Native OpenShell returned RESOURCE_EXHAUSTED:
`caller has reached the durable mutation admission limit; unresolved requests require reconciliation`.
Both owned sandboxes were closed. No denied operation or prior model request was resent.

Read-only inspection of the database open by the exact dedicated gateway process found:

| Observation | Count |
| --- | ---: |
| Retained claims in the caller bucket | 1,000 |
| Completed claims | 995 |
| Unresolved claims | 5 |
| Completed claims already eligible for expiry | 0 |
| Invalid stored claim payloads | 0 |

Only aggregate states/timestamps were queried using SQLite `mode=ro` and `query_only=ON`.
No raw request payloads, credentials or claim identities were disclosed or changed. The
live WAL was included; immutable mode was not used. The gateway's open descriptors identify
its store; the standalone gateway supplies a default path even though the server library
requires a configured database URL.

Pinned [OpenShell mutation admission](https://github.com/NVIDIA/OpenShell/blob/6648bd0c290efbc41ba131ee9831ee45cd431f94/crates/openshell-server/src/grpc/mutation_replay.rs)
counts all retained claims, including completed operations. Its limit is 1,000 per caller.
Successful claims become eligible for pruning after 24 hours; unresolved claims do not
expire. The error message alone therefore does not establish an unresolved-operation leak.
There is no status/list/acknowledgement/reconciliation RPC for this ledger in the pinned
schema. Resource inspection and deletion do not release these claims.

Earliest completed claims become eligible on **2026-10-06 at 15:56:03 UTC (11:56:03 EDT)**.
The latest observed completion becomes eligible at **21:11:22 UTC (17:11:22 EDT)**.
Capacity starts reopening gradually; this does not guarantee a complete cohort fits within
one admission window. Repeated confinement observations also consume claims. A sustained
full-cohort qualification needs sufficient supported native capacity; bypassing the ledger,
resetting it, changing caller identity to evade the limit or reducing safety checks is not
qualification evidence. No such workaround was performed.

A separate safety defect was confirmed in the pinned execution handler: native timeout can
emit synthetic exit code 124 without terminal claim finalization. The harness now treats
124 as ExecutionUnknown, conservatively including an explicit process exit 124 because
these are indistinguishable. It does not record a completed local receipt, closes the
owned sandbox and retains the sticky dispatch fence across worker restart. Ordinary
nonzero exits remain completed, replayable receipts. No native limit, request ID, retention,
provider policy or isolation setting changed.

Current live correction verification remains **not_checked** after this admission block;
the last full-cohort gate remains **failed**, with quality and unsafe-negative gates
**not_checked**. No promotion is supported. Native/model requests are stopped until
admission capacity is available; no future run is scheduled implicitly.

Private evidence: `.harness/openshell/private/live-eval-v11-263616ced211/`.
`native-admission-counts.json` SHA-256:
`6d8c1e63d5d022efe463bde09b0219b834f29a453e47855e3f0fd1f479a5e5e4`.

Timeout-correction validation: 269 deterministic tests passed with required real Temporal;
lint, compilation and generated-contract/instruction checks passed. Network test deselected.

The quota-blocked diagnostic completed four model responses before admission was denied.
Both owned sandbox records were closed and exact owned-ID reconciliation passed.
Completed native history replay passed (169 events, zero model/native dispatches).

## Lifecycle reuse and operation accounting

The harness now performs the confinement audit once per sandbox lifecycle. A durable
proof binds the sandbox's native ID, metadata/spec/configuration revisions, process
identity, provider attachment, TLS configuration and actual container identities/start
times. Every reuse still checks current native readiness, provider readiness and the
outer fence. Missing, incomplete or changed proof closes owned work; it never repeats
an uncertain audit. The audit request ID is persisted before dispatch. Worker/adapter
restart uses this same proof. Per-investigation workspace/model sandboxes and per-probe
sandboxes remain separate. No workflow scheduling contract changed; v11 remains current.

Evaluation reports now count local durable create, admission, execution and capture
receipts separately from model tokens and tool calls. Incomplete intents remain unknown.
Native ledger occupancy, remote-worker visibility and cleanup are not established by
these counts. Legacy proof files overwrote repeated audits, so historical counts are
lower bounds. These observations and cohort estimates do not authorize dispatch or
establish a native capacity budget.

Read-only projection of the five completed cases and one failed case in the preserved
`live-eval-v11-201cc101da4a/cohort.json` found 257 completed receipt operations, with
completed-case counts ranging from 28 to 49. Retaining those observed operations and
extrapolating to the 30 unobserved cases gives **1,097–1,727** operations. This is a
historical workload estimate, not qualification of the new reuse behavior; unsampled
cases can exceed that range. A full cohort cannot be assumed to fit a 1,000-claim window.

A fresh read-only gateway observation at **2026-10-05 21:35:36 UTC** still found
1,000 claims, 995 completed, five unresolved and zero expired successes. No native or
model dispatch was attempted. Earliest expiry remains as recorded above.

Official release inspection found latest stable still
[v0.1.2](https://github.com/NVIDIA/OpenShell/releases/tag/v0.1.2). The admission source
on [inspected main](https://github.com/NVIDIA/OpenShell/blob/be7af99ff2eacba807d82b69adb0c3d4eaa32158/crates/openshell-server/src/grpc/mutation_replay.rs)
is byte-identical to the pinned implementation; there is no supported capacity setting
or admission reconciliation API. Resolving sustained capacity requires an upstream
bounded configurable quota and occupancy API. Reclaiming unresolved entries requires
native execution evidence while preserving permanent non-reexecution fences for unknown
outcomes. Upgrading to an unqualified development build does not resolve this limit.

Validation: **279 deterministic tests passed**, one network test deselected, with required
Temporal CLI 1.9.1. Lint, compilation and generated API/instruction checks passed.
Historical native replay again passed: 169 events, zero native/model dispatches.
Native lifecycle reuse and current live quality remain **not_checked** because admission
capacity is unavailable. Existing failed Maven and full-cohort gates remain unchanged.

| Report | SHA-256 |
| --- | --- |
| `diagnostic.json` | `66fc2702a8fb7cdd44ae56b54b3c260d6f8281be921a9513b07f057459d18aef` |
| `diagnostic-failure.json` | `4717f3b50129e6f90a0414243b101c2068478e705502654083f523650328d05a` |
| `diagnostic-history.json` | `cd928cf31317381c7b676dd3b6c5d2bc73a68083d7fb84b3c3f85379a9577574` |
