# Minimal native inference executor

Use the operator deployment and migration instructions in
the [broker runbook](../../docs/broker/RUNBOOK.md). After any change to the executor's packaged
sources, rebuild the image and qualify it again before brokered use.
The executor image includes the typed inference protocol, codec, compatible model
adapter, and their hash-pinned dependencies. It excludes the controller, database,
worker, tool execution, and provider credentials.

Generate a fresh private context using the checkout's pinned Python environment:

```bash
.harness/bin/mise exec -- uv run --locked python deploy/openshell/build_context.py \
  --machine aarch64 --output .harness/openshell/executor-context
```

Build through the already qualified runsc build-egress builder. Supply the checkout's
actual builder name and approved build proxy; do not use a host Docker context:

```bash
.harness/bin/docker buildx build --builder <checkout-runsc-builder> \
  --build-arg HTTP_PROXY=<approved-build-proxy> \
  --build-arg HTTPS_PROXY=<approved-build-proxy> \
  --output type=docker,dest=.harness/openshell/executor.tar \
  .harness/openshell/executor-context
```

Load the artifact into the dedicated OpenShell daemon and record its observed manifest
SHA256. The complete executor contract must use that immutable digest and the approved
supervisor digest. The native adapter checks actual workload images and confinement;
image names and configured runtime strings are insufficient evidence.

## Native qualification

`infosec_harness.qualification.broker.native` is a bounded, mock-provider acceptance check. It
uses the production controller, native adapter, executor and durable ledger with three
registered scopes: `local`, `temporal` and `cachepoint`, each with one static invocation. It
rejects any contract whose backend or model is not the module's mock backend and mock model.
It requires a private operator JSON file referenced by `IH_NATIVE_FIXTURE_CONFIG`, containing
`native` (the `NativeDeploymentConfig` fields), the full `contract`, `controller_origin`,
`controller_ca` and `scope`. Native specs are keyed by the full contract digest; the approved
effective policy and observed provider ID/version/profile digests must come from actual
operator inventory. This is not a production issuance policy.

Start the counted mock HTTPS provider where the executor's provider route reaches it. Its
gateway provider record must hold only the module's fixed test canary. Write its stats beside
the operator configuration as `native-mock-stats.json`:

```bash
.harness/bin/mise exec -- uv run --locked python -m infosec_harness.qualification.broker.native \
  mock-provider --bind-address <guest-address> --port 18443 \
  --certificate <cert.pem> --private-key <key.pem> --stats-file <config-dir>/native-mock-stats.json
```

Start the trusted acceptance controller with a migrated private test database and real TLS
certificate, using `--factory infosec_harness.qualification.broker.native:controller_factory`.
The controller alone receives gateway mTLS/admin access and the dedicated Docker socket. The
executor receives neither host mounts nor database access. Then:

```bash
.harness/bin/mise exec -- uv run --locked python -m infosec_harness.qualification.broker.native worker
.harness/bin/mise exec -- uv run --locked python -m infosec_harness.qualification.broker.native prove
```

The first command runs a real Pydantic AI agent through the production broker. The second
checks authentication rejection, committed result retrieval, actual native close, repeat
close and saved results after closure while asserting the independent mock provider counter
remains unchanged. It writes a sanitized `native-<scope>-proof.json` beside the private
operator configuration. The `temporal` scope adds an acceptance-only ACK barrier after
production ledger completion (`native-temporal-committed.json` / `native-temporal-release`
in the same directory); its host runner terminates a worker, retrieves the same saved request
on retry and replays history with sends forbidden. The `cachepoint` scope sends the actual
`render_prompt` output with an authored SDK CachePoint and checks its exact retained
representation plus one counted provider send before the authentication, saved-result and
native-close assertions. See `src/infosec_harness/qualification/broker/native_temporal.py` for the
Temporal host runner's strict operator inputs; `tests/runtime/test_broker_native_temporal.py`
runs it only when `HARNESS_NATIVE_TEMPORAL_CONFIG` is set.

Preserve failed-attempt evidence. Stop only corroborated owned resources, and run
`scripts/openshell_guest.py stop` inside the checkout-owned guest after all dedicated
Docker containers and containerd tasks are gone. The helper refuses closure if shared
firewall, forwarding, route, or bridge invariants differ. A native create acknowledged
before its ID is persisted requires manual ownership reconciliation; the broker
refuses to acknowledge cleanup or delete an uncorroborated resource by name.


## Authorized local-provider qualification

The live runners are separate from mock acceptance and live in
`infosec_harness.qualification.broker`. Prepare an immutable reviewed manifest naming the
endpoint and model explicitly (there are no defaults), the frozen per-agent cases and dataset
hashes, the candidate direct and brokered model files, the broker catalog, a zero-price policy,
and the declared ordered phases (`direct`, `native-local`, `native-temporal`). The manifest's
source commit must be the clean checkout HEAD, and its report directory must be inside the
checkout so sandbox temporary files are guest-visible.

```bash
PILOT="uv run --locked python -m infosec_harness.qualification.broker.pilot"
$PILOT --manifest <manifest.json> --manifest-sha256 <sha256>
$PILOT --manifest <manifest.json> --manifest-sha256 <sha256> --phase direct --allow-inference
$PILOT --manifest <manifest.json> --manifest-sha256 <sha256> \
  --phase local --allow-inference --baseline-report <pilot-dir>/direct.json
```

`scripts/broker_real_provider_check.py` is an equivalent wrapper.

The default `validate` phase resolves every agent's direct and native route from the frozen
files without constructing a client and makes no provider call. Each phase of a manifest is
claimed once and runs in its own reaped child. A native phase compares against a passed direct
phase of the same manifest: exact effective settings, endpoint, resolved model, capability
profile, full budget and price inputs must match; only transport fields and the catalog-bytes
component of the pricing identity may differ. The user must authorize the provider and data
scope before execution.

`scripts/broker_real_graph_check.py` freezes, then executes once by digest, one complete
production Temporal graph per pilot and phase with real sandbox build/probe execution,
persisted API checks and root/child replay with external I/O forbidden. Generated temporary
build inputs stay in a private trial `TMPDIR` visible to the checkout-owned Lima guest.

Earlier live results, retained failures and remaining rollout gates are in
[`CREDENTIAL_BROKER_LIVE_PROVIDER.md`](../../docs/evidence/2026-10-01-broker-implementation/CREDENTIAL_BROKER_LIVE_PROVIDER.md).
No endpoint discovery response attests deployed tokenizer identity or upstream
authentication. Never resend `completion_unknown` requests when changing images.


## Comparing a recorded controller configuration

`scripts/openshell_controller_configuration.py` is an importable operator validation utility.
It does not inspect Docker, load credentials, start containers, or establish ownership.
Use `configuration_digest(saved_inspect)` to compare the complete `Config`, `HostConfig`,
`Mounts`, and `NetworkSettings` projection. Both mount-record arrays are sorted; all
other configuration values remain exact. Keep inspection files private because `Config`
can contain credentials.

`validate_replacement_host_config(old_host_config, new_host_config, created=True)`
checks a newly created replacement against an explicitly recorded old null
`OomKillDisable`. A created replacement must have boolean false. With `created=False`,
the running replacement may have null or boolean false, reflecting Docker's default
and unsupported-option representation. True, numeric zero, missing fields, and every
other HostConfig difference are rejected. The actual running OOM value remains part
of the configuration digest; later health checks compare that recorded value exactly.

Before using either result for recovery, independently authenticate the exact issued
container IDs, process identity, source and image pins, mounts, TLS, and retained state.
A matching digest grants no permission to start, adopt, retry, release, or delete anything.

Run `pytest tests/development/test_openshell_controller_configuration.py` for the pure
regressions. Serving code, executor images, model controls, budgets, and durable workflow
identities are unaffected; this utility requires no replay generation change.


## Parent-prepared boundary seccomp candidate

`Dockerfile.sandbox-backport` and `.dev-tools/openshell-sandbox-backport.json`
record a separate arm64 boundary build on the unchanged pinned OpenShell source.
Patch 0003 prepares the existing seccomp BPF bytes before fork and installs those
bytes in the child without tracing or recompilation. The BPF rules, compatibility
filter order, mandatory no-new-privileges, Landlock baseline and child self-protection
remain unchanged. Existing provider-readiness and startup-control patches retain
separate provenance. This local patch is not an NVIDIA release.

The confirmed source defect is tracing through the production OCSF writer mutex
from post-fork `pre_exec`. The deterministic regression deliberately holds that
mutex: the original path must block, while raw prepared installation and the actual
capability-free integration must finish and retain syscall denials. This proves the
source defect; it does not establish the cause of a historical native startup failure.
Compilation, image loading and native startup each need their own measured evidence.

The recipe runs exact unprivileged tests with non-symlink artifact selection and
rejects missing/duplicate test names. A positive Landlock ABI >=3 query is mandatory
because one upstream behavioral test otherwise returns without exercising enforcement.
The GNU binary must load in both the unified image and the actual executor Python
rootfs with network disabled, read-only filesystem, no capabilities and nonroot UID.
No shared libraries may be added to make a failing artifact load.

Supply the hash-pinned source and tool archives declared in the manifest. The local
base tag in the recipe is an operator input: load the retained attested base and
verify its actual ID equals the manifest's base digest before and after `--pull=false`
build. Bare `sha256:<local image ID>` is not a portable registry reference. If the
base is published later, use its independently verified repository@digest reference;
never resolve an arbitrary replacement tag. The canonical recipe hash and exact
measured private build recipe hash are recorded separately.

Activation requires the same fresh immutable digest for gateway `supervisor_image`
and `sandbox_runtime_image`, removal of `supervisor_bin`, and an owned gateway reload:
the Docker driver caches boundary bytes when constructed. Retain the previous image,
configuration and host boundary artifact. Reconfirm each actual lease's image, full
contract and confinement before untrusted execution. No wire schema, retry, timeout,
admission budget, idempotency, cancellation or durable workflow behavior changes.
Rollback uses exact retained images/configuration and the same ownership checks;
all uncertain requests/reservations remain held and must never be resent. Build/test
success alone does not change rollout or qualification status.

The boundary's unchanged PTY code calls `nix::pty::openpty` through locked nix0.29.0.
Its GNU target needs `libutil.so.1`, included explicitly in the closed dependency list.
This adds no library to either image. The upstream sandbox release staging target is
musl; this candidate deliberately uses GNU2.28 with actual loader validation in both
existing root filesystems, and does not claim to reproduce the official sandbox ABI.

The measured private V8 recipe completed with Rust1.95 formatting, both new
regressions, all fourteen existing isolation guards and GNU2.28 symbol checks passed.
Its exact hash is distinct from the canonical recipe hash because the canonical
header and patch filename differ. The retained unified image was not rebuilt for
loader validation. Both strict loader attestations passed: the unified image loaded
the binary, and a derived copy of the existing executor image added only that binary
with mode0555, then ran it nonroot/read-only/network-none/capability-free. This avoids
copying files into a read-only container; it adds no runtime libraries or source code.
The source build commit and actual image/binary hashes are recorded in the manifest.
The old-runtime100-startup zero-model diagnostic also passed. Neither result identifies
the cause of the earlier intermittent startup failure. The new candidate's native
startup and full-agent qualification remain `not_checked` until separately executed.
