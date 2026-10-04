# Minimal native inference executor

Use the operator deployment and migration instructions in
[`CREDENTIAL_BROKER_RUNBOOK.md`](../../docs/architecture/CREDENTIAL_BROKER_RUNBOOK.md).
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

`tests/runtime/broker_native_fixture.py` is a bounded, mock-only qualification factory. It
uses the production controller, native adapter, executor, and durable ledger, with
four explicitly registered fixture scopes: `frozen`, `temporal`,
`temporal-rerun`, and `cachepoint`. It rejects other provider/model targets. It requires a private
operator JSON file referenced by `IH_NATIVE_FIXTURE_CONFIG`, containing `native`
(the `NativeDeploymentConfig` fields), the full `contract`, `controller_origin`,
`controller_ca`, and `fixture`. Native specs are keyed by the full contract digest;
the approved effective policy and observed provider ID/version/profile digests must
come from actual operator inventory. This is not a production issuance policy.

Start the trusted fixture controller with a migrated private test database and real
TLS certificate, using `--factory broker_native_fixture:controller_factory` and
`PYTHONPATH=src:tests/runtime`. The controller alone receives gateway mTLS/admin access and
the dedicated Docker socket. The executor receives neither host mounts nor database
access. After reviewed infrastructure and the mock HTTPS provider are ready:

```bash
.harness/bin/mise exec -- uv run --locked python tests/runtime/broker_native_fixture.py worker
.harness/bin/mise exec -- uv run --locked python tests/runtime/broker_native_fixture.py prove
```

The first command runs a real Pydantic AI agent through the production broker. The
second checks authentication rejection, committed result retrieval, actual native
close, repeat close, and saved results after closure while asserting the independent
mock provider counter remains unchanged. It writes a sanitized proof beside the
private operator configuration. The Temporal fixture adds a test-only worker ACK
barrier after production ledger completion; its host runner terminates a worker,
retrieves the same saved request on retry, and replays history with sends forbidden. The
`cachepoint` scope sends the actual `render_prompt` output with an authored SDK
CachePoint and checks its exact retained representation plus one counted provider
send before authentication, saved-result, and native-close assertions.
See `tests/runtime/broker_native_temporal_fixture.py` for its strict public operator inputs.

Preserve failed-attempt evidence. Stop only corroborated owned resources, and run
`scripts/openshell_guest.py stop` inside the checkout-owned guest after all dedicated
Docker containers and containerd tasks are gone. The helper refuses closure if shared
firewall, forwarding, route, or bridge invariants differ. A native create acknowledged
before its ID is persisted requires manual ownership reconciliation; the broker
refuses to acknowledge cleanup or delete an uncorroborated resource by name.


## Authorized local-provider qualification

The live runners are separate from mock qualification. Prepare an immutable reviewed manifest for the endpoint, model, cases, settings
and budgets. Use `scripts/broker_real_provider_check.py` to validate its digest and
execute direct, native LocalOps and native Temporal phases. Inference requires `--allow-inference`; native phases require the retained
`--baseline-report`. Comparison checks exact effective settings, endpoint,
authored budgets and semantic pricing inputs, retaining separate transport catalog
hashes. Use `--help` for current commands. The user must authorize the provider
and data scope before execution.

`scripts/broker_real_graph_check.py` freezes and executes one complete production
Temporal graph with real sandbox build/probe execution, persisted API checks and
root/child replay with external I/O forbidden. Each manifest has an exclusive
execution marker. Generated temporary build inputs stay in a private trial
`TMPDIR` visible to the checkout-owned Lima guest. A separately frozen correction
for the verified host temporary-directory defect requires retained terminal
failure, replay and cleanup; it does not rerun a prior manifest.

Live results, retained failures and remaining rollout gates are in
[`CREDENTIAL_BROKER_LIVE_PROVIDER.md`](../../docs/validation/CREDENTIAL_BROKER_LIVE_PROVIDER.md).
No endpoint discovery response attests deployed tokenizer identity or upstream
authentication. Never resend `completion_unknown` requests when changing images.


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
