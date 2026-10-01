# Credential broker implementation evidence

Date: 2026-10-01
Status: implementation and qualification in progress; rollout disabled

This record covers the isolated `feature/openshell` worktree based on remote `develop`
`51fe66eb7459ce8f75a0d73931cf85867b78cefc`. The original checkout's unrelated reorganization
and uncommitted changes are excluded. The [plan](../architecture/CREDENTIAL_BROKER_IMPLEMENTATION_PLAN.md),
[frozen protocol](../architecture/CREDENTIAL_BROKER_PROTOCOL.md),
[operator runbook](../architecture/CREDENTIAL_BROKER_RUNBOOK.md) and
[G0 feasibility evidence](OPENSHELL_FEASIBILITY.md) identify scope and topology.

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
| Layer C final-image lifecycle qualification | not_checked | Final frozen image, saved result/auth/close and shared cleanup checks running |
| Layer D real Temporal service recovery/replay | passed | Real service/worker kill, activity attempt 2, one operation/two allocations, saved result, 65-event broker history and 39-event current direct history replay; zero replay I/O; native adapter is a shim |
| Pre-change workflow history replay | passed | Runtime loaded exclusively from git archive of exact 51fe66 baseline, 39-event history replayed under current broker config with broker I/O patched to fail; zero sends |
| Layer D final OpenShell recovery | not_checked | Real native integration remains separate from the service shim recovery gate |
| Registered local/eval parity | passed | Real registered context agent, local tools and typed output; eval uses durable production configuration identity; mock native adapter |
| Full deterministic suite | passed | Integrated source run: 2161 passed, 25 skipped, 859 warnings in 75.77s; skips include 11 explicitly gated service cases |
| Installed-wheel packaging | passed | Installed no-deps wheel outside checkout: disabled 11-agent catalog, migration 0005/0004 and controller/executor module entrypoints |
| Generated artifacts and development skills | passed | OpenAPI, shared instructions and canonical development-skill drift checks |
| Final shared runsc/build-egress preservation | not_checked | Earlier real fixture passed; rerun after native lane cleanup |
| P7 provider compatibility, tokenizer bound, held-out evaluation | not_checked | Numeric backend/model request/token/spend budget not recorded; no paid calls authorized |
| UI checks | not_applicable | No frontend changes |
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
from committed artifacts and must be rotated before handoff.

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
`pg-ledger-f5ff51e4d76b4de38f12f7d24425b261.json` and
`service-9ce9ab566ad04c77b22b63211a30bd77.json`. The original failed reports remain retained
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
