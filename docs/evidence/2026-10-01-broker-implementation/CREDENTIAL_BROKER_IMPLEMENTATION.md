# Credential broker implementation evidence

Date: 2026-10-01
Status: implementation ready for review; bounded mock/native checks and direct live workflow passed; native live compatibility failed; rollout disabled

This record covers the isolated `feature/openshell` worktree based on remote `develop`
`51fe66eb7459ce8f75a0d73931cf85867b78cefc`, now integrated with remote `develop`
`4988450e21dc61f67f86a980e62af4264dc53fa7`. Its canonical test/UI reorganization is preserved;
the original checkout was not edited by this work. The [plan](CREDENTIAL_BROKER_IMPLEMENTATION_PLAN.md),
[frozen protocol](../../broker/PROTOCOL.md),
[operator runbook](../../broker/RUNBOOK.md) and
[G0 feasibility evidence](../2026-10-01-openshell-feasibility/OPENSHELL_FEASIBILITY.md) identify scope and topology.

## Contracts and implementation

Workers retain model tools and have only a TLS/HMAC controller channel. Brokered models
construct no provider client or direct provider key. The controller issues nonsecret run/
invocation bindings against the existing root BudgetLedger, provisions run/full-contract
OpenShell executors lazily, and validates runtime policy, attachment, process and image
evidence. The minimal executor can claim and complete only already admitted inference;
it has no database, native administration, probe or checkout authority.

The ledger migration is additive revision `0005`. Root revision compare-and-swap and unique
request identities prevent concurrent budget over-allocation and duplicate dispatch. One
winning dispatch permit is persisted before provider send. Responses are committed before
worker acknowledgement. Unknown completion never resends; allocation remains held for
completed, failed and unknown requests. Observed provider usage cannot release uncertainty.

Each model contract includes `ih-inference-v1`, PydanticAI 2.49.0, OpenShell 0.1.2, effective
settings/adaptations, native driver, empty inspection, immutable images and permission
identity. Brokered contract/configuration hashes change explicitly. Optional binding/contract
fields are omitted in direct-mode serialization, preserving legacy payload identity.
Provider credential revision is operational provenance and does not change access identity.
Only redundant generated provider labels are normalized; every rule and duplicate count
remains in the policy digest, with exact native attachment verified separately.

## Durable recovery assessment

Local/eval invocations have a bounded persisted root and close scoped native resources in
`finally`. Temporal records `credential-broker-invocation-v1`, includes workflow run identity
in owned reservations and schedules issuance/cleanup as activities. Model request identity
uses Temporal activity scheduling identity, excluding retry attempt. Replay cannot perform
controller/provider I/O. A dedicated new broker task queue is required; existing direct
workers must drain their historical queue. Histories cannot silently switch transport.

Expired dispatch bindings may retrieve the identical committed result through authenticated
read-only `/v1/results`; they cannot provision, admit, claim or send. Run tombstones precede
revocation and native cleanup, fencing new admissions after restart. Unknown completion and
missing retained history require explicit operator recovery; v1 replacement is unsupported.

## Gate status

| Gate | Status | Evidence / limit |
| --- | --- | --- |
| G0 dedicated OpenShell feasibility | passed | Bounded native prototype; see separate G0 record |
| G1 frozen contracts | passed | Strict wire fixtures, ownership, transition and budget contracts |
| Deterministic implementation checks | passed | Focused profiles, transport, ledger, controller/executor and workflow tests; canonical lint/compile/agent validation |
| PostgreSQL ledger/admission | passed | Actual PostgreSQL 16.15: 57 cases including abrupt process termination and concurrent CAS |
| Layer B real TLS processes | passed | Real HTTPS controller/executor, PostgreSQL 16.15, mock provider; final combined B/D/eval/baseline run: 11 tests, 10 counted sends, cleanup verified |
| Layer C production-native executor smoke | passed | One actual worker Agent request through production controller/native adapter/ledger/executor returned exact mock output with one counted approved provider request; policy/attachment/image/process verified |
| Layer C final-image lifecycle qualification | passed | Frozen image/source byte equality; signed native request, unsigned/auth denials, saved response after idempotent closure, exact owned resource removal and shared invariant preservation |
| Layer D real Temporal service recovery/replay | passed | Real service/worker kill, activity attempt 2, one operation/two allocations, saved result, 65-event broker history and 39-event current direct history replay; zero replay I/O; native adapter is a shim |
| Pre-change workflow history replay | passed | Runtime loaded exclusively from git archive of exact 51fe66 baseline, 39-event history replayed under current broker config with broker I/O patched to fail; zero sends |
| Layer D native single-agent recovery | passed | Real production native path: SIGKILL after commit, activity attempt 2 recovered same persisted ID, exactly one provider send, 11-event replay zero I/O; explicit `Agent[str]` scope |
| Layer D full registered native graph | not_checked | Single-agent native recovery and registered local/eval service-shim checks do not qualify the complete production workflow graph |
| Registered local/eval parity | passed | Real registered context agent, local tools and typed output; eval uses durable production configuration identity; mock native adapter |
| Full deterministic suite | passed | Current source: 2268 passed, 40 skipped, 861 warnings in 71.89s; skipped service/native cases are separately accounted for in live-provider evidence |
| Installed-wheel packaging | passed | Installed no-deps wheel outside checkout: disabled 11-agent catalog, migration 0005/0004 and controller/executor module entrypoints |
| Generated artifacts and development skills | passed | OpenAPI, shared instructions and canonical development-skill drift checks |
| Final shared runsc/build-egress preservation | passed | Actual post-cleanup runsc positive/negative, bounded execution, PID/memory exhaustion, internal proxy allow/deny, isolated builder and forced-removal cleanup fixtures |
| Preserved development stack smoke | passed | API/UI/storage readiness, S3 put/get/delete and retained sentinel, fresh complete stub workflow/result and Temporal visibility; no provider calls |
| P7 direct local-provider compatibility | passed | Authorized frozen `<self-hosted-endpoint>` pilot: all eleven agents passed; see [current live-provider evidence](CREDENTIAL_BROKER_LIVE_PROVIDER.md) |
| P7 native local-provider compatibility | failed | Finite live trials stopped after failures; final supervisor capture records stale policy generation; ten uncertain requests remain fenced; no redispatch |
| P7 deployed tokenizer and held-out evaluation | not_checked | Published-tokenizer bounds do not attest the deployed runtime; eleven compatibility cases do not establish held-out quality acceptance |
| UI checks | passed | Requested follow-up: formatting, two frontend tests, TypeScript and production Vite build; no frontend source changes |
| Rollout | not_checked | Packaged catalog disabled; production acceptance requires all applicable gates |

## Retained failures and limits

The initial shared-runsc OpenShell qualification failed Landlock and caused a topology
revision, not a relaxed confinement expectation. The G0 record retains an intermittent
primary Docker OOM notification failure; an unchanged rerun passed, and its reliability
risk remains unresolved. During production qualification, actual native service URLs and
Docker security-option syntax differed from mock assumptions; the adapter and tests were
corrected to observed upstream schema. YAML strict sequence validation rejected an explicit
empty inspection list before dispatch; JSON-mode schema validation now preserves strict
scalars while accepting YAML's array representation, with a regression.

Automatic approval review rejected removing the expired worker binding dispatch check.
The implementation instead adds read-only result recovery while preserving expiry on every
new dispatch. A test diagnostic exposed a checkout-only PostgreSQL password; it is excluded
from committed artifacts. The checkout-only role password was rotated after native cleanup;
fresh authentication passed, its private environment was atomically updated, and checkout
services were restarted without deleting volumes.

Qualification uses test-only canaries. Private PKI, native databases, lease keys, raw logs,
image archives and environment files remain ignored beneath `.harness/`; reports and this
record contain sanitized identities and counts. Lower-cost delegation was limited to
configuration, transport fixtures, packaging and documentation; capable owners retained
auth, policy, transaction and native enforcement work. Available cost usage is unknown;
no measured savings are claimed.


The real worker-restart gate initially failed closed with a request conflict and one send.
Retained field-path diagnostics isolated set-valued SDK `deferred_capability_ids` array
ordering. The pinned SDK declares both this field and `revealed_tool_names` as `set[str]`;
canonical serialization sorts only their order and retains every member. Changed membership
still changes request identity. The corrected actual restart recovered the identical saved
request and finished with exactly two sends for tool call and structured result.

Other regressions transfer operation ownership at controller binding issuance, before
admission, so worker settlement cannot release a delayed broker envelope; skip durable close
before any owned reservation exists; and build retained intake generations as replay-only
static model profiles when a new deployment selects brokering. Current intake still requires
the approved atomic contract. No historical generation gains dispatch authority.

Sanitized local reports are retained under ignored `.harness/reports/credential-broker/`:
final post-merge `pg-ledger-f342623bb2bc4303b8b0011d9b966c86.json` and
`service-36606b22c1b74ae6b8146eac3dfa947e.json` (57 cases in 5.46s and 11 cases in
34.75s, respectively); prior successful reports are also retained. The original failed reports remain retained
with explicit statuses and no secret values. These local files are not published in the PR.


Independent capable review identified a close/provisioning race and over-broad permanent
error classification. Lifecycle closure now fences the ledger and persistent run identity,
then serializes resource cleanup with the provisioning lock; provisioning rechecks revocation
before native mutation and readiness. Transient `unavailable`/`pending` model errors have a
distinct bounded-retry class and preserve the exact request ID and payload. Issuance and
cleanup activities classify terminal dispositions explicitly. Permanent/unknown completion
never gains retry or replacement authority. Focused regressions cover the reviewed cases;
independent lifecycle re-review passed 99 focused tests. Native qualification is recorded
separately and does not confer P7 acceptance.

Native creation has an acknowledged-resource/persisted-ID crash gap. If creation succeeds
but the controller dies before recording the exact native ID, restart fails closed and
requires operator reconciliation. It does not adopt or delete a similarly named resource,
or acknowledge successful closure while an unconfirmed owned resource remains. This v1
limit is retained rather than hidden by a broad cleanup operation.

## Final native source and cleanup identity

The qualified executor image is
`sha256:8c555bfdbaf88c6192796ef09edca4a388a34c6f70d5456f82a2699e52332e86`.
All six minimal-executor source hashes were checked unchanged after the develop merge.
The native C proof, narrow native Temporal D report/history, fresh post-D signed/auth/close
proof and scoped reconciliation are retained privately as `p4-frozen-proof.json`,
`p4-native-d-report.json`, `p4-native-d-report.history.json`,
`p4-temporal-rerun-proof.json` and `p4-final-native-cleanup.json` beneath
`.harness/openshell-spike/`. Native provider counts were observed at the local mock,
not inferred from a configured backend name. Native workloads and run-scoped ledger
credential providers were removed using corroborated IDs and labels; the dedicated
Docker/containerd were stopped after task inventory was empty. Shared firewall,
forwarding, route and bridge snapshots matched. Test data/images remain retained.
Eighteen native logs/proofs/stats passed fixture-canary/placeholder scans with positive
controls. These artifacts are local evidence, not material to publish in the PR.

The initial narrow native Temporal attempt recovered the saved response but its test
postprocessing incorrectly called the SDK usage property as a function. That failed attempt
was retained and its workflow/workers cleaned up. The corrected fixture passed in 24.78s;
no production expectation was weakened. P7 and full native graph acceptance remain explicit
follow-up gates, so this branch is submitted for review with broker rollout disabled.

The post-merge stack smoke initially reused an older completed demo that was absent from
upstream develop's newly selected `temporal_visibility` database. The old completed workflow
and persisted result remained intact. A fresh controlled stub demo completed with sandbox
execution and was queryable in the new visibility index; the unchanged full stack smoke then
passed. Initial and successful logs are retained separately. No historical workflow or
volume was deleted, and no visibility migration/backfill is claimed.

## Follow-up: all agents and end-to-end execution

The user's all-agent validation request expanded the earlier context-only transport check.
All eleven registered agents ran through production `LocalOps` with deterministic stub models
and returned typed outputs with one SDK model request each. The sanitized matrix is retained
as `all-agents-887947b65f96416e9f1d63334ad11445.json` under the private report directory.

The expanded real HTTPS/PostgreSQL/Temporal qualification passed **24 cases in 63.42s**, with
exactly **39 counted local mock-provider sends**: 10 existing service/recovery requests,
11 registered local agent requests, seven prepare/triage graph requests, and 11 registered
durable agent requests. Every sweep agent produced its expected typed output, committed
its request row and closed its owned root. The graph retained original rendered prompts,
prepared successfully and exercised recon, env-planner, context, probe-planner, probe-author,
probe-diagnosis and verdict in order. Repair and intake agents were exercised by the explicit
matrix because normal successful triage does not necessarily select those branches.
The all-agent durable workflow's **355-event history replayed with zero broker/provider I/O**.
Prior killed-worker recovery, current direct and exact pre-change history replay still passed.
Database, processes and private fixtures were cleaned up. Report:
`service-f52c6b52b3bd47e0bf78ba00443bd20b.json`. This lane uses a native adapter shim and
simulates graph sandbox execution; it measures transport and orchestration, not judgment
accuracy or full native graph acceptance.

A separate fresh controlled workflow on the actual checkout stack, `batch-63836e23cfbe116d`,
completed, persisted its result, and was queryable through Temporal visibility. Its ready
sandbox recorded one successful probe with precondition and sink-returned markers. The
successful path used six agents; cached preparation bypassed env-planner on this run.
No branch coverage is inferred from that cache hit. The direct/broker matrices and separate
uncached broker graph cover the remaining agent execution paths. Sanitized report:
`end-to-end-batch-63836e23cfbe116d.json`.

The expanded graph check found an actual runtime defect: the initial broker codec rejected
production `render_prompt` cache boundaries as non-text content. The corrected codec
preserves only the pinned SDK's exact `CachePoint` kind/TTL representation and ordering;
unknown fields and remote/binary content remain prohibited. Regressions first reproduced the
failure, then passed. Independent review passed 61 focused tests and separately confirmed
TTL-dependent digest identity, denied invalid/multimodal/subclass markers, and unchanged
canonical bytes for previously accepted plain payloads. `ih-inference-v1` and the request-ID
algorithm are unchanged; the expanded supported subset and new immutable image are explicit
contract/provenance changes. Old bindings cannot silently acquire the new image.

The final native image for this corrected source is
`sha256:ae16ecf1020072b8afac9f3fc9c3989933586f7ece82a3d8525aef10540cb0cb`, with qualified
full-contract digest `95fe90e9b1b184ddf4a4bd8a5a746f17da012d502b820ef7388fc9901a5d95f2`.
Actual rendered CachePoint input reached the production native executor and remained exactly
`{"kind":"cache-point","ttl":"5m"}` in its committed request. One independent local mock
send returned usage 3/2. Worker authentication rejection, denied worker ledger access,
retained result and repeat real closure passed without another send. This native follow-up
used a private SQLite ledger; PostgreSQL transaction/service behavior is qualified separately.
Six final source hashes match the image. Owned native workloads/lease credentials and
containers were removed; gateway/mock/controller and dedicated Docker/containerd were stopped;
shared firewall/forwarding/routes/bridges matched. Seven retained logs/proofs/stats passed
secret scans with positive controls. Private evidence:
`p4-cachepoint-proof.json`, `p4-cachepoint-source-sha256.json` and
`p4-cachepoint-cleanup.json` beneath `.harness/openshell-spike/`. The earlier image/proofs above
remain historical evidence for their exact source; this is the current qualified image.

The PR's backend and web CI jobs passed, but its conformance job exposed a relative tool-path
bug: `agentctl` was looked up after changing into the temporary mirror. The runner now resolves
the operator checkout path before that change. Three subprocess regressions and actual local
conformance passed with the existing AGENT029 waivers unchanged; no thresholds were relaxed.
A service test also needed to recognize the exact native OpenSSL certificate-required alert
alongside the existing HTTP transport exception. Other raw SSL failures are not accepted;
missing-certificate provider sends remain zero. Failed qualification attempts are retained.

Final deterministic suite: **2,179 passed, 40 skipped, 861 warnings in 78.71s**. Twenty-four
explicit service cases and the native gate ran separately, not through implicit skip success.
Canonical lint/compile/agent checks, generated artifacts and development skills passed.
UI formatting, two frontend tests, type checking and production build passed. Real-provider
compatibility/tokenizer bounds/held-out evaluation and the complete native production graph
remain `not_checked`; no paid calls or production accuracy claims were made.

The post-follow-up primary sandbox gate first **failed** its unchanged memory-exhaustion
expectation: exit 137 at a configured 64 MiB bound, but Docker reported `OOMKilled=false`.
This reproduces the previously retained OOM-notification reliability issue. An unchanged
rerun **passed** all actual runsc positive/negative, bounded execution, PID/memory exhaustion,
proxy allow/deny, isolated builder and cleanup fixtures. Both logs are retained as
`all-agents-final-sandbox.log` and `all-agents-final-sandbox-rerun.log`. The successful rerun
does not resolve the intermittent failure; sandbox gate reliability remains **failed**,
and no expected state or threshold was weakened. Agent execution and the actual completed
sandbox probe are separate observations from this infrastructure reliability limitation.


## Later real-provider qualification status

Later timing, cancellation and ownership-gated cleanup corrections and the fixed-category
error relay are recorded in [native rerun evidence](CREDENTIAL_BROKER_NATIVE_RERUN.md).
Behavior 0.2.6 passed 2,409 deterministic tests plus canonical and CI gates. Its fresh
`1199a499...` executor image passed eleven native readiness/cleanup checks, and separately
frozen recon and partial-build diagnostics passed execution, semantic scoring and cleanup.
These are limited passes: the full native pilot remains failed, with intake's expanded
skill context exceeding the unchanged conservative input cap, and native Temporal/graph
acceptance remains not_checked. The final retained ledger contains 15 uncertain and 80
completed requests; all 119 leases are deleted and native sandbox inventory is empty.
Dedicated infrastructure remains running for follow-up, with the uncorroborated provider
untouched. No held request was released or resent. Hosted deployment and tokenizer/weight
attestation gates remain separate and not_checked; rollout stays disabled.
