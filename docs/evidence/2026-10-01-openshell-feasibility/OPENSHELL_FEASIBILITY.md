# OpenShell feasibility evidence

Date: 2026-10-01
Status: G0 feasibility passed; bounded prototype approved; production contract work next
Branch: `feature/openshell`
Baseline: remote `develop`, `51fe66eb7459ce8f75a0d73931cf85867b78cefc`

The initial OpenShell v0.1.2 sandbox failed its Landlock qualification under
the harness-managed Docker daemon's default `runsc` runtime. This historical
failure remains a stop condition for that topology. The later bounded G0
prototype passed feasibility review; no production model routing, credential
provider, ledger, or direct-access fallback was added. Later qualification used
only the test credential fixture described below.

The worktree is `<worktree>`. It excludes
the original checkout's unrelated staged changes and repository reorganization.
The GitHub base branch is lowercase `develop`; `Develop` does not exist.

## Reproducible inputs

The upstream release is v0.1.2, source commit
`6648bd0c290efbc41ba131ee9831ee45cd431f94`. Artifact hashes and OCI index identities
are retained in [the manifest](../../../.dev-tools/openshell.json). The macOS arm64
CLI and Linux arm64 gateway, supervisor, and sandbox archives were downloaded,
SHA-256 verified, and executed. OCI metadata retrieval does not establish image
execution. The Python SDK wheel and Linux x86-64 artifacts were not executed.

The separate checkout-owned Lima VM uses the unchanged pinned
[managed runtime template](../../../deploy/dev-runtime/lima.yaml): Docker 29.1.3,
runsc 20260921.0, Lima 2.2.0, Ubuntu arm64 image digest
`sha256:7bcf159e29ad0000bfed9c57875908c39268f5ed1257f4958fa6a9f5f60edd54`.
Its runtime home is recorded in `.harness/runtime-home`; no host Docker context
or original checkout VM configuration was changed.

The workload image was resolved before the launch to
`ubuntu@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3`.
The supervisor image was configured using the manifest's immutable OCI digest.
The native gateway used worktree-local test PKI, loopback binding on port 17670,
mTLS user authentication, and disabled loopback plaintext service HTTP.
Private key files and database contents are intentionally excluded from this report.

## Initial runsc attempt checkpoint: actual observations

1. Gateway configuration preflight passed. Native gateway startup and CLI status
   reported version 0.1.2, connected, authenticated with mTLS transport. A request
   with the correct CA but no client certificate failed its TLS handshake. This
   verifies the gateway channel only, not future executor admission authentication.
2. A provider-free sandbox was requested with the pinned workload image and command
   `sleep 300`. It entered Error before readiness. Its log reported
   `ControlSupervisorStartFailed`, incompatible Landlock access rights, and
   `Landlock allow/deny probe` child exit status 1. There was no successful inference
   executor process or model request.
3. The pinned Docker driver source has no runtime-selection field in either strict
   gateway or per-sandbox configuration. Its workload and host supervisor container
   configurations omit runtime and inherit the daemon default. A JSON runtime
   override would be rejected, rather than select a different boundary.
4. After the failed launch, an explicit `--runtime=runsc --network=none` container,
   with all capabilities dropped and no-new-privileges, wrote and independently
   checked a temporary marker. Docker still reported default runtime `runsc`.
   This is a positive execution check, not the full build-egress acceptance suite.
5. Deletion of only `ih-p0-runsc` was requested. Acknowledgement alone is not proof
   of completed cleanup; subsequent gateway listing reported no sandboxes, and Docker listing by the
   checkout-owned OpenShell namespace label returned no containers. The owned
   native gateway was then stopped by verified process identity. The managed VM
   and local evidence/data are preserved; no unrelated processes were stopped.

The exact launch command was:

```bash
XDG_CONFIG_HOME="$PWD/.harness/openshell-spike/config" \
OPENSHELL_LOCAL_TLS_DIR="$PWD/.harness/openshell-spike/tls" \
.harness/openshell-spike/openshell sandbox create \
  --name ih-p0-runsc \
  --from ubuntu@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3 \
  --no-auto-providers --detach --no-tty -- sleep 300
```

The CLI printed an Error but returned zero for this failed provisioning attempt.
Future enforcement runners must assert the observed sandbox phase and successful
workload marker; process exit status alone is insufficient.

## Initial P0 work and runsc checkpoint checks

This table records the initial runsc checkpoint; the final requalification table
below supersedes its time-sensitive gate statuses.

- Added an artifact manifest and checksum-before-publication downloader. It neither
  extracts archives nor deploys a gateway. Unit tests cover corrupt caches, partial
  failures, symlinks, path traversal, invalid URLs, and all manifest entries.
- Added a test-only TLS mock OpenAI-compatible upstream with counted allowed and
  denied requests, bounded request handling, no retained source bodies or headers,
  and a canary/placeholder detector with positive leakage controls.
- Bounded `temporalio` to `>=1.33,<1.34`, fixing a baseline installed-wheel failure:
  Temporal 1.34's `EventGroup` type cannot be represented by the pinned PydanticAI
  schema. All nine existing installed-wheel tests passed after the correction.
  Lock metadata changed; resolved Temporal remains 1.33.0. No workflow or schema
  behavior changed and no histories were migrated.

| Gate | Status | Evidence / limit |
| --- | --- | --- |
| Pinned arm64 archives | passed | Download hashes checked against upstream release metadata and manifest |
| Gateway mTLS reachability | passed | Live authenticated CLI status and no-client-cert rejection |
| OpenShell confinement on existing daemon | failed | Actual Landlock qualification failure before readiness |
| Existing runsc positive execution | passed | Confined container marker checked after failure; daemon default unchanged |
| Full build-egress and runsc acceptance | not_checked | Positive execution is not the complete acceptance runner |
| Credential substitution / restricted ledger channel / executor auth | not_checked | No ready executor or provider attachment |
| Rotation, detach, policy enforcement, controller recovery | not_checked | Dependent runtime tests blocked by confinement |
| `just check` / `just generated-check` / `just dev-skills-check` | passed | Canonical checks in worktree-local pinned environment |
| Canonical full suite | passed | Final run: 1858 passed, 14 skipped, 859 warnings |
| G0 | failed | Required executor confinement unavailable on this topology |
| G1–G4 | not_checked | Dependent implementation and acceptance deliberately not started |
| Paid provider calls | not_checked | Zero calls; no explicit spend budget received |
| Frontend / runtime schema generation | not_applicable | No frontend, schema, or runtime contract edits |

Initial baseline run: 1836 passed, 14 skipped, three installed-wheel failures.
After the dependency correction and final scanner regression checks: 1858 passed,
14 skipped, 859 warnings in 61.61 seconds.
Service-dependent skips do not establish Temporal replay or live recovery.
The full suite's cost warnings are from stub models and do not establish spend
accounting. No paid provider dispatch was authorized or executed.

Transient output remains under `.harness/openshell-spike/`, including
`runtime-bootstrap.log`, `gateway.log`, `runsc-launch.log`, `final-suite.log`,
`packaging-fixed.log`, `final-scanner-suite.log`, and the image manifest. Do not publish that directory:
it also contains test private keys and native gateway state.

## Decision and next work

Review [the concrete deployment revision](OPENSHELL_DEPLOYMENT_REVISION.md)
and final evidence below. Independent capable review approved the bounded G0
prototype after cleanup was repeated and verified. The next work is production
contract design; P1–P8 and the requested completed implementation PR remain
pending.

## Corrected dedicated-daemon start (2026-10-01)

The complete `./dev` baseline passed before the OpenShell daemon work: actual
runsc and build-egress acceptance, API/web/storage readiness, and a Temporal
persisted-stub smoke. The first dedicated Docker 29.1.3 start with
`bridge=none` removed the unused primary `docker0` bridge and its routes. Its
known child container briefly started and then stopped. The failure is retained
here; it did not qualify the OpenShell runtime.

The lead restored the same primary bridge identity (MAC `8e:c8:32:9d:57:04`,
IPv4 `172.17.0.1/16`) and reran the real runsc and build-egress checks; both
passed. The corrected OpenShell daemon uses the pre-created named user bridge
`ihos0c3cae03c0`, subnet `172.29.255.0/30`, address `172.29.255.1`, `RA=0`,
and `UP` before the startup snapshot. There is no `bip`; iptables, ip6tables,
forwarding and masquerading are disabled. Docker's implicit system-containerd
reuse was avoided with a separate private containerd config root, state and
socket. The daemon startup passed shared firewall, route and forwarding
invariants. At this historical startup checkpoint, the native mTLS gateway was
running against its separate Docker socket
`/var/lib/ih-openshell/0c3cae03c0/run/docker.sock`; pinned images were loaded.

At this checkpoint sandbox launch/readiness and credential substitution were
still `not_checked`; the later section records their qualification. No production
model routing or paid provider calls have occurred. The original runsc Landlock
failure above remains valid evidence for that topology, and the bridge correction
does not weaken its expected outcome.

| Updated check | Status | Evidence / limit |
| --- | --- | --- |
| Full harness `./dev` baseline | passed | Actual runsc and build-egress, API/web/storage readiness, Temporal persisted-stub smoke |
| Primary Docker bridge restored after first-start regression | passed | Same observed MAC and IPv4; real runsc/build-egress rerun passed |
| Dedicated daemon shared firewall/routes/forwarding invariants | passed | Corrected pre-created named user bridge and private containerd configuration |
| Native mTLS gateway connected to dedicated daemon socket | passed | Gateway running with separate socket; does not establish executor readiness |
| OpenShell sandbox launch/readiness and native confinement | not_checked | This is the corrected-daemon-start checkpoint; later final evidence records qualification |
| Credential substitution / restricted ledger / executor admission | not_checked | This is the corrected-daemon-start checkpoint; later final evidence records qualification |
| G0 | not_checked | Startup correction alone did not satisfy G0 |
| Production routing / paid provider calls | not_applicable | No integration or provider dispatch performed |

## Final G0 requalification observations (2026-10-01)

The corrected sandbox reached `Ready` with the hard Landlock requirement: host
Landlock ABI v8 and supervisor policy V3 were applied to all 12 required paths,
with no skipped paths. `NoNewPrivs=1` and `Seccomp=2` were observed in the actual
provider-free executor. The immutable test executor image was
`sha256:518f63c240f127ba5319fad55f1a1ad7dfdf8c9fac767b601319c1b61091b6c7`,
built from Python image `sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f`.
The test supervisor image was
`sha256:a594138847f466bd6f19e9975215b39fe6e0d5e1eebcf7b8783b39549686334b`,
based on the pinned OpenShell supervisor with the proper mock root-CA bundle.

The effective provider-composed policy source was the sandbox policy. It allowed
only `POST 192.168.5.15:18443/v1/chat/completions` and `POST /ledger/g0`, with
the reviewed destinations limited to `/32` addresses and executable identity
`python3.12`. Enforcement mode was `enforce`; TLS terminated in the executor
with upstream certificate re-verification, with no TLS skip. The workload used
`network=none`, runtime `runc`, UID/GID 65532,
`privileged=false`, and only the named channel volume. No host bind, Docker
socket, or database authority was available to it.

The provider-free executor ran the marker, could not read `/root/.profile` or
write `/etc/ih-forbidden`, could not escalate to UID 0, and received raw-socket
error 93. Forbidden credential/resource paths were absent. The workload
environment contained only a placeholder matching the expected native
OpenShell placeholder pattern, which was asserted by regex. Retained logs and
counts were scanned and contained none of the v1/v2 canaries or native
placeholder. Missing executor HMAC admission returned 401
with zero HTTP requests to provider or ledger. This HMAC is an ingress proof for
the bounded prototype, not reservation or budget authority. A correctly signed
test request returned 200 with marker and usage 3/2 and exactly one counted
ledger and provider request. The malformed wrong-path request returned 403 and
caused zero provider HTTP requests. Metadata-network access was blocked; a timeout
alone is not treated as proof of that block.

Direct-egress enforcement also passed a separate actual workload allow/deny
pair. The `ih-p0-egress` workload used `urllib` with `ProxyHandler({})`, ignoring
proxy environment variables. Its approved `POST /v1/chat/completions` request
with the native placeholder returned 200 and usage 3/2. The same opener and
placeholder sent to forbidden `POST /v1/not-allowed` received 403. The counted
mock reported provider=1, ledger=0, denied=0, confirming no forbidden request
reached the HTTP fixture despite proxy bypass.

The first HTTPS fixture used a self-signed CA:TRUE certificate as the server
leaf; that specific chain failed validation. The fixture was corrected to use a
separate proper CA and leaf certificate. With the
correct SAN but untrusted CA, and with a trusted CA but wrong IP SAN, the executor
returned 502 and provider/ledger HTTP counts stayed zero in both cases.

Credential rotation was exercised against the real service. Detaching v1 returned
a receipt confirming revocation of the credentials, policy, and future
environment; detach did not install the rotated credential. The persistent
executor then returned 502; the ledger counter increased, but provider count and
mock denied count did not change. The provider was separately updated to v2,
then a distinct new-process v2 executor, ID
`ba385b0e-2409-4a16-8a43-0c2d4530da00`, returned 200. Its mock accepted only
the new canary; the independent TLS unit test confirms v1 is rejected after
rotation. Restarting the native gateway as a fresh process rediscovered the same
executor ID in `Ready`; no automatic provider request occurred (count remained
one), and the next authorized request raised it to two. This demonstrates the
observed gateway discovery/reconciliation primitive only. Future harness
controller/ledger recovery behavior remains `not_checked`.

Cleanup was repeated after review. Deletion acknowledgement was followed by a
native sandbox list with no entries and a dedicated-daemon `docker ps -a` with no
containers. Exact gateway and mock PIDs were identity-checked before stopping.
The helper stop verified all containerd tasks drained; the shared firewall/route
snapshot remained unchanged. The dedicated daemon and private containerd were
stopped, their state and evidence retained, and runtime status reported false.

The full original runsc/build-egress acceptance rerun passed unchanged alongside
the corrected daemon. Docker emitted its OOM-before-die evidence for the
successful concurrent check. A separate earlier concurrent memory failure exited
137 with `OOM=false`: kernel cgroup evidence showed the kill, but Docker emitted
no OOM event. This intermittent notification risk remains unresolved and was not
used to weaken code or expected outcomes. The owned-bridge IPv6/DAD correction
and stable route/firewall snapshots are detailed in the [deployment revision](OPENSHELL_DEPLOYMENT_REVISION.md).

| Final check | Status | Evidence / limit |
| --- | --- | --- |
| OpenShell Ready and Landlock V3 path coverage | passed | Host ABI v8; all 12 paths applied; no skips |
| Provider-free filesystem/process/network controls | passed | Marker, file allow/deny, UID 0 denial, raw socket error 93, forbidden paths absent |
| Effective sandbox policy | passed | Exact provider and ledger POST paths, `/32` destinations, Python 3.12 identity |
| Signed executor admission and counted provider/ledger marker | passed | Missing signature 401/zero HTTP; valid signature 200 and one send each |
| Credential rotation / gateway restart discovery / cleanup | passed | Distinct v2 executor; old-canary denial unit regression; observed gateway primitive; verified removal and stop |
| TLS CA and SAN rejection | passed | Both invalid trust cases 502 with zero service HTTP counts |
| Direct-proxy-bypass verification | passed | Actual workload ignored proxy environment; approved path succeeded and forbidden path returned 403 with no second mock HTTP request |
| Harness controller/ledger crash recovery | not_checked | Native gateway rediscovery is not evidence for future harness control-plane recovery |
| Full production integration and paid-provider gates | not_checked | Production contracts/routing and paid calls were not implemented or exercised |
| Full canonical `just test` | passed | 1936 passed, 14 skipped, 859 warnings, 61.97 seconds |
| `just check` / `just generated-check` / `just dev-skills-check` | passed | Final canonical checks |
| Independent capable G0 review | passed | Approved bounded feasibility prototype after cleanup condition was reverified |
| Production routing / paid provider calls | not_checked | No production integration or paid dispatch |

G0 feasibility passed and the bounded prototype was approved. Production
contracts are next; P1–P8 remain unimplemented. No production routing or paid
provider dispatch occurred.

Upstream sources:
[release](https://github.com/NVIDIA/OpenShell/releases/tag/v0.1.2),
[Docker Engine 29.1.3 release](https://github.com/moby/moby/releases/tag/v29.1.3),
[Docker configuration](https://github.com/NVIDIA/OpenShell/blob/v0.1.2/crates/openshell-driver-docker/src/lib.rs#L153),
[supervisor launch](https://github.com/NVIDIA/OpenShell/blob/v0.1.2/crates/openshell-driver-docker/src/lib.rs#L4955),
[workload launch](https://github.com/NVIDIA/OpenShell/blob/v0.1.2/crates/openshell-driver-docker/src/lib.rs#L5763).

Delegation used an independent capable source/security reviewer and a bounded
`gpt-6-luna` support agent for inventory, fixture, and artifact-helper work.
Token/cost metrics were unavailable; no savings estimate is asserted. The lead
reviewed changes, repaired integration issues, and retained independent expected
outcomes. The additional daemon used for this qualification was stopped after
verification; its data and local evidence remain available for review.
