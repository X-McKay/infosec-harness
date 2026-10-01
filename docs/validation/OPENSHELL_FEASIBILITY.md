# OpenShell feasibility evidence

Date: 2026-10-01
Status: G0 failed; integration remains disabled
Branch: `feature/openshell`
Baseline: remote `develop`, `51fe66eb7459ce8f75a0d73931cf85867b78cefc`

The real OpenShell v0.1.2 sandbox failed its Landlock qualification under the
harness-managed Docker daemon's default `runsc` runtime. The implementation
plan makes executor confinement a stop condition. No production model routing,
credential provider, ledger, or direct-access fallback was added.

The worktree is `/Users/al/.codex/worktrees/openshell/infosec-harness`. It excludes
the original checkout's unrelated staged changes and repository reorganization.
The GitHub base branch is lowercase `develop`; `Develop` does not exist.

## Reproducible inputs

The upstream release is v0.1.2, source commit
`6648bd0c290efbc41ba131ee9831ee45cd431f94`. Artifact hashes and OCI index identities
are retained in [the manifest](../../.dev-tools/openshell.json). The macOS arm64
CLI and Linux arm64 gateway, supervisor, and sandbox archives were downloaded,
SHA-256 verified, and executed. OCI metadata retrieval does not establish image
execution. The Python SDK wheel and Linux x86-64 artifacts were not executed.

The separate checkout-owned Lima VM uses the unchanged pinned
[managed runtime template](../../deploy/dev-runtime/lima.yaml): Docker 29.1.3,
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

## Actual observations

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

## Completed P0 work and checks

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

## Next decision

Review [the concrete deployment revision](../architecture/OPENSHELL_DEPLOYMENT_REVISION.md)
before restarting G0. Keeping the harness daemon unchanged and giving OpenShell
its own native-runtime daemon is a proposed topology, not a tested replacement
or an automatic fallback. P1–P8 and pushing/opening the requested completed
implementation PR remain pending.

Upstream sources:
[release](https://github.com/NVIDIA/OpenShell/releases/tag/v0.1.2),
[Docker configuration](https://github.com/NVIDIA/OpenShell/blob/v0.1.2/crates/openshell-driver-docker/src/lib.rs#L153),
[supervisor launch](https://github.com/NVIDIA/OpenShell/blob/v0.1.2/crates/openshell-driver-docker/src/lib.rs#L4955),
[workload launch](https://github.com/NVIDIA/OpenShell/blob/v0.1.2/crates/openshell-driver-docker/src/lib.rs#L5763).

Delegation used an independent capable source/security reviewer and a bounded
`gpt-6-luna` support agent for inventory, fixture, and artifact-helper work.
Token/cost metrics were unavailable; no savings estimate is asserted. The lead
reviewed changes, repaired integration issues, and retained independent expected
outcomes. No additional daemon has been deployed.
