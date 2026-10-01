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

`tests/broker_native_fixture.py` is a bounded, mock-only qualification factory. It
uses the production controller, native adapter, executor, and durable ledger, with
three explicitly registered fixture scopes: `frozen`, `temporal`, and
`temporal-rerun`. It rejects other provider/model targets. It requires a private
operator JSON file referenced by `IH_NATIVE_FIXTURE_CONFIG`, containing `native`
(the `NativeDeploymentConfig` fields), the full `contract`, `controller_origin`,
`controller_ca`, and `fixture`. Native specs are keyed by the full contract digest;
the approved effective policy and observed provider ID/version/profile digests must
come from actual operator inventory. This is not a production issuance policy.

Start the trusted fixture controller with a migrated private test database and real
TLS certificate, using `--factory broker_native_fixture:controller_factory` and
`PYTHONPATH=src:tests`. The controller alone receives gateway mTLS/admin access and
the dedicated Docker socket. The executor receives neither host mounts nor database
access. After reviewed infrastructure and the mock HTTPS provider are ready:

```bash
.harness/bin/mise exec -- uv run --locked python tests/broker_native_fixture.py worker
.harness/bin/mise exec -- uv run --locked python tests/broker_native_fixture.py prove
```

The first command runs a real Pydantic AI agent through the production broker. The
second checks authentication rejection, committed result retrieval, actual native
close, repeat close, and saved results after closure while asserting the independent
mock provider counter remains unchanged. It writes a sanitized proof beside the
private operator configuration. The Temporal fixture adds a test-only worker ACK
barrier after production ledger completion; its host runner terminates a worker,
retrieves the same saved request on retry, and replays history with sends forbidden.
See `tests/broker_native_temporal_fixture.py` for its strict public operator inputs.

Preserve failed-attempt evidence. Stop only corroborated owned resources, and run
`scripts/openshell_guest.py stop` inside the checkout-owned guest after all dedicated
Docker containers and containerd tasks are gone. The helper refuses closure if shared
firewall, forwarding, route, or bridge invariants differ. A native create acknowledged
before its ID is persisted requires manual ownership reconciliation; the broker
refuses to acknowledge cleanup or delete an uncorroborated resource by name.
