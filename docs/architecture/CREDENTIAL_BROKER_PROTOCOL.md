# Credential broker protocol v1

Status: frozen interface for P2–P4 implementation, pending independent implementation review.

`inference/protocol.py` is the canonical strict wire schema. PydanticAI 2.49 typed messages,
request parameters, settings, and responses are serialized with a restricted codec; text,
local tool calls/results, retry prompts, and structured output definitions are supported.
Remote media, uploaded files, native tools, streaming, custom URLs/headers, extra-body,
and unknown settings/parts are rejected before admission. The three existing Bedrock cache
settings are preserved as known inert fields on the OpenAI path with strict value validation;
this matches existing authored agent specs and does not enable Bedrock brokering. Tools remain on the worker.
Provider adaptations run once in the executor. No provider transport retries are enabled.

The trusted worker calls the controller API with deployment HMAC authentication over
method, exact path, expiry, and canonical body. TLS is mandatory; credentials are loaded
outside workflow inputs. Existing root reservations are the sole spending authority.
The controller verifies agent, accepted configuration, root deadline, operation ownership,
run/invocation and complete contract against its operator catalog. The worker cannot mint
limits. Local/eval invocations first obtain an explicitly bounded persisted root reservation;
eval mode uses the durable production configuration identity and closes each case scope;
Temporal invocations reference the existing RootAccounting operation through a patched
workflow path. Old histories stay direct and unchanged. Only nonsecret binding references
are serialized in AgentDeps. Retry attempts never participate in logical request identity.

Controller admission inserts a unique request and suballocates the existing invocation
reservation in one BudgetLedger revision transaction. Trusted bounds use worst-case input
and output token caps and price ceilings; unknown pricing cannot admit paid calls. Completed,
pending, failed and unknown requests all retain their allocation in v1. Worker settlement
cannot release a broker-owned operation. This conservative rule also covers tool/run/time
dimensions, while real provider usage is retained independently for reconciliation.

The controller allocates native sandboxes lazily by run plus full contract digest. It
corroborates policy, immutable image, profile attachment and enforcement from the native
control plane before readiness. Provider revisions are operational evidence and rotation
creates a fresh executor. OpenShell 0.1.2's verified CLI is the initial lifecycle adapter;
CLI status exit codes alone cannot establish readiness. No custom credential driver or
inspection framework is added: native driver identity and empty inspection bindings are
explicit. Unsupported configured extensions fail closed.

Worker channel credentials never enter the executor. Each executor has a distinct,
lease-scoped inference channel identity and native ledger provider binding. Ledger auth
is injected only at the two exact ledger endpoints. The restricted executor API accepts
only an already admitted request for its run/contract/lease. Its ledger channel can claim
and complete those requests; it cannot create reservations or invoke lifecycle/admin APIs.
The controller retains all root-budget/database/native gateway authority.

Ledger interface owned by P3:

- `admit(request, *, lease_id, allocation)` returns a stored request disposition. Allocation
  is calculated by trusted admission code, never taken from the worker wire payload.
- `claim(request_id, *, lease_id)` atomically transitions accepted to dispatch_intent and
  returns DispatchPermit. Exactly one claimant may send. No timeout reclaims this permit.
- `complete(result, *, permit)` saves a validated response before worker acknowledgement.
- `fail_before_dispatch(request_id, *, lease_id)` terminalizes only accepted requests.
- `recover(request_id, *, lease_id)` fences an unresolved dispatch to completion_unknown;
  it never resends. Retained terminal identities are never silently re-created.
- `get(request_id)` retrieves the retained disposition/result; scope is checked by admission.

Admission verifies existing reservation and expiry on every new request. A reused ID with a
different payload/binding/contract is conflict with zero send. Result retries retrieve one
saved response. Failure after dispatch intent, including response parsing or lost commit,
retains possible spend and fails explicitly. Replacement attempts are deferred: operator
recovery returns an explicit unsupported disposition, never a fresh automatic dispatch.
Cancellation revokes admission and the native lease without claiming upstream cancellation.
Controller restart reconciles only resources bearing its deployment/run/contract ownership;
foreign resources are never adopted or removed. Tombstones persist past lease cleanup.

Exclusive implementation ownership: lead protocol/codec/shared integration/versioning;
P2 profiles/transport and their tests; P3 ledger/admission, additive DB model/migration and
tests; P4 native adapter/controller/executor, deployment files and tests. Interface changes
require lead review before dependent edits. No lane changes another lane's source files.


Expired worker bindings retain their inference-dispatch expiry check. Lost acknowledgements
may instead call authenticated `/v1/results`, a read-only lookup of the identical retained
request. Its channel signature lifetime is independent of reservation expiry because it
cannot provision, admit, claim, or send. Missing, pending, failed and unknown records return
an explicit disposition. A saved result is returned with its already committed provenance.
The change preserves the distinction between identity authentication and spending authority.


Observed native schema required one policy identity refinement: provider-composed network
map labels include per-lease resource UUIDs. `inference/policy.py` removes only generated
`_provider_` map labels and their matching redundant `name` field, retaining every rule,
default, authored label, ordering within rules, and duplicate rule count. Composed entries
are sorted by canonical bytes. The native adapter separately verifies exact attachment,
profile export digest, provider resource revision, and lease ownership before comparison.
Extra/broader rules, altered process/filesystem/TLS permissions, or inconsistent generated
names fail readiness. Credential resource labels do not change the permission identity.


The two pinned SDK set-valued parameter fields, `deferred_capability_ids` and
`revealed_tool_names`, are serialized in sorted order. Membership, tool definitions and
visibility semantics are retained exactly; this removes hash-seed ordering differences
across worker restarts without accepting any changed permission or payload data. Controller
binding issuance marks its operation broker-owned atomically before any admission, so
worker settlement cannot release authority for a delayed request.


Worker activity retries distinguish `TransientBrokerError` (`unavailable` or `pending`)
from permanent `BrokerError` dispositions. They retry the exact retained logical request
and payload at most three times; controller claim fencing remains the sole dispatch
authority. Issuance activities similarly retry transient infrastructure failure, while auth,
policy, budget, identity, conflict, expiry, invalid response and unknown completion remain
non-retryable. This does not add executor/provider retries or authorize a replacement ID.

## Authored graph cache markers

The supported SDK message subset includes `CachePoint` between text items in a user prompt,
as emitted by the production `render_prompt`. Preserve exactly `kind: cache-point` and
`ttl: 5m | 1h`, their ordering and all surrounding text. Extra fields, invalid TTLs,
subclasses and remote/binary content are rejected. This corrects the initial v1 codec's
rejection of normal graph prompts; the request-ID algorithm and previously accepted plain
payload bytes remain unchanged. The rebuilt executor image changes its full contract/config
identity, so deployments must select the matching image rather than silently replacing an
executor behind an existing binding. Historical replay retains its no-I/O behavior.
