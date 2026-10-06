# Native provider readiness — 2026-10-05

The fresh v11 cohort at `f7b6656` completed two native self-hosted model responses,
then its third request disconnected. All cases except the first remained unstarted.
Captured supervisor logs identify the immediate close mechanism: OpenShell ended the
model tunnel because its captured policy generation 1 became stale against generation 2.
The failed external request remains unknown and is not resent. Both owned sandboxes
closed and explicit reconciliation passed.

## Observed native failure

At 19:28:27.709 UTC, the gateway returned the provider environment. At 19:28:37.750,
it returned the same environment revision. At 19:28:37.752, the supervisor denied the
active model tunnel with `policy generation is stale [captured_generation:1 current_generation:2]`.
The native model executor recorded an APIConnectionError without a complete response.
This explains this observed disconnect; it does not conclusively attribute the older
incident, whose supervisor logs were unavailable.

Inspection of pinned OpenShell v0.1.2 identifies a startup bookkeeping path: captured
provider credentials are returned without recording their installation in the readiness
tracker. The first refresh sees the tracker waiting for credentials and reloads policy,
invalidating active tunnels. Current upstream installs captured environments through the
tracker, but the next tagged releases are prereleases. This candidate retains the pin.

Primary sources: [v0.1.2 supervisor](https://github.com/NVIDIA/OpenShell/blob/v0.1.2/crates/openshell-supervisor/src/lib.rs),
[upstream corrected startup path](https://github.com/NVIDIA/OpenShell/blob/e7fdd6beef98f7f92d86271a169fdd4d3be44cf3/crates/openshell-supervisor/src/lib.rs).

## Admission change

Before returning a model sandbox, the adapter waits for OpenShell's exact native provider
readiness receipt. Its receipt binds sandbox/provider identity, attachment/environment/
configuration revisions and policy hash. Ready requires observed installed credentials,
active policy and installed launch environment, together with session/process/network
identities. Pending status RPCs may repeat within a deadline; revoked, superseded,
withheld, failed or malformed observations fail closed. No model or execution operation
is retried. A fixed delay, provider name or sandbox Ready phase does not qualify admission.

The readiness proof is saved privately beside confinement evidence. Existing safeguards
and the output feedback remain. Activity-internal admission changes keep the v11 workflow
graph, while its worker fingerprint changes and old workers must stop before replacement.
Future real policy/provider changes may still invalidate connections; unknown execution
remains fenced.

## Preserved evidence

Private directory: `.harness/openshell/private/live-eval-v11-6f10b30fa262/`.

| File | SHA-256 |
| --- | --- |
| `cohort.json` | `711f98067ac13d115dd98dc8a7260f9071444be57d1aeed7658ed8437c11bdba` |
| `first-case-failure.json` | `032eac11e99eaa9bbfc1f14cb4414d6dec49ecfa2b5ed80e485608d5d2e9ebdd` |
| `first-case-history.json` | `8db485231262c933642716bec78d174d3bba4364e28a862516a6508492b4cf1c` |
| `failure-summary.json` | `2320bd37c94f14eebfc102db68c335638648b8a15fd6765cab7be9a1abacc94d` |
| `native-gateway.log` | `287c134ef41d030bab5d208eddeff0fc6a01e5ad06bc937166aaedc0ecb43bca` |
| `native-qualification.json` | `3e3b55768c113d83a2031d84e2220f05b67bc06412ba151b35808a402642df7a` |
| `supervisor-931ad08c-4d41-4bca-bf41-ce4d4886065c.log` | `4ce856ecbb9c5f42d604fc134cdd8a4931dbd443aafb1beca29bf4a8123c5c51` |
| `supervisor-648febf8-0b5c-40ff-9ddf-77571bc983d7.log` | `0963fa476dd7516303a78610fefc045075d60b53a5ea20871601baa894293be7` |

A fresh real native model admission passed in 10.93 seconds with zero model calls and
successful cleanup. The archived exact receipt proves installation and matching revisions,
not just a configured state. Private report `provider-readiness-control.json` SHA-256:
`b5014847a8123aed3fbb57bf99593a0f958b5ac8d0433227dbc9cf8231392533`.

The full deterministic suite passed 257 tests with pinned real Temporal required. A
subsequent code-only RPC-error hardening passed the focused OpenShell suite; lint,
compilation and generated drift checks passed. Readiness regression expectations come
from the pinned native receipt contract. Empty initial epochs/zero fingerprints remain
valid where the native contract permits them; matching observed installation is required.
