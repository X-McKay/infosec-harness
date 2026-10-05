# OpenShell runtime

The investigator runs one Temporal workflow through the checkout's native OpenShell runtime.
The workspace, offline probe and model executor are separate native profiles. The repository
does not fall back to direct model access or ordinary Docker when OpenShell qualification fails.
OpenShell release archives and OCI image identities are pinned in
[`.dev-tools/openshell.json`](../../.dev-tools/openshell.json).

## Prepare the checkout-owned runtime

Use the canonical setup entry point. Full setup checks the managed VM, actual runsc builder,
control plane and configured native runtime; offline mode intentionally leaves native runtime
and live inference `not_checked`.

```bash
./dev --profile offline
# Configure the dedicated gateway and runtime JSON described below before full setup.
./dev
```

Download release archives only through the manifest-checking helper. It validates SHA-256
before publishing files beneath `.harness/openshell/artifacts/`; the separate official-image
OCI digests remain in the same manifest.

```bash
for artifact in cli-macos-arm64 gateway-linux-arm64 supervisor-linux-arm64 sandbox-linux-arm64 sdk-wheel; do
  .harness/bin/mise exec -- uv run --locked python scripts/openshell_artifacts.py "$artifact"
done
```

Build the workspace/toolchain image only through the already qualified runsc build-egress
builder. `.harness/dev.env` supplies its checkout-local builder and approved proxy; it is a
private file, so do not print it or commit the resulting log or tar. The image is then streamed
into the dedicated guest daemon without selecting a host Docker context:

The qualified workspace base is the official `python:3.12.13-slim-bookworm` image pinned by
the manifest-verified index digest
`sha256:4766d8b510c428e595d74b9cc5bbb2fae8e26316fffb4adc89908d79aacd58a2`. Bookworm supplies
OpenJDK 17, which supports both the Java 7 compatibility corpus and Java 17 corpus. The
observed Java executables are `/usr/lib/jvm/java-17-openjdk-arm64/bin/java` and
`/usr/lib/jvm/java-17-openjdk-arm64/bin/javac`; workspace policies should allow only those
observed compiler/runtime paths when Java package egress is needed.

```bash
set -a
source .harness/dev.env
set +a
.harness/bin/docker buildx build -f deploy/openshell/Dockerfile.workspace \
  --builder "$HARNESS_BUILDX_BUILDER" \
  --build-arg HTTP_PROXY="$HARNESS_BUILD_EGRESS_PROXY" \
  --build-arg HTTPS_PROXY="$HARNESS_BUILD_EGRESS_PROXY" \
  --output type=docker,dest=.harness/openshell/workspace.tar deploy/openshell

CHECKOUT_ID="$(basename "$(cat .harness/runtime-home)")"
LIMA_VERSION="$(awk -F= '$1 == "LIMA_VERSION" {print $2}' .dev-tools/versions.env)"
LIMA_HOME="$(cat .harness/runtime-home)" \
  ".harness/tools/lima-${LIMA_VERSION}/bin/limactl" shell --tty=false --workdir "$PWD" h \
  sudo --non-interactive docker \
  --host "unix:///var/lib/ih-openshell/$CHECKOUT_ID/run/docker.sock" load \
  <.harness/openshell/workspace.tar
```

Record the resulting image ID from the load/inspect result in each workspace and probe profile.
The copy-up of apt-owned files and the package installation intentionally run in one Dockerfile
layer because the runsc BuildKit overlay cannot create dpkg backup hardlinks to lower-layer
files.

Build the separate, minimal model executor from the current module and hash-locked dependency
closure. The context generator copies only `model_executor.py`; choose a new output directory
for each build. It contains no Temporal worker, controller, repository snapshot or credentials.

```bash
.harness/bin/mise exec -- uv run --locked python deploy/openshell/build_context.py \
  --machine aarch64 --output .harness/openshell/executor-context
set -a
source .harness/dev.env
set +a
.harness/bin/docker buildx build -f .harness/openshell/executor-context/Dockerfile \
  --builder "$HARNESS_BUILDX_BUILDER" \
  --build-arg HTTP_PROXY="$HARNESS_BUILD_EGRESS_PROXY" \
  --build-arg HTTPS_PROXY="$HARNESS_BUILD_EGRESS_PROXY" \
  --output type=docker,dest=.harness/openshell/executor.tar \
  .harness/openshell/executor-context

CHECKOUT_ID="$(basename "$(cat .harness/runtime-home)")"
LIMA_VERSION="$(awk -F= '$1 == "LIMA_VERSION" {print $2}' .dev-tools/versions.env)"
LIMA_HOME="$(cat .harness/runtime-home)" \
  ".harness/tools/lima-${LIMA_VERSION}/bin/limactl" shell --tty=false --workdir "$PWD" h \
  sudo --non-interactive docker \
  --host "unix:///var/lib/ih-openshell/$CHECKOUT_ID/run/docker.sock" load \
  <.harness/openshell/executor.tar
```

Record the loaded image ID from the native daemon's load/inspect result in the model profile.
The executor's provider-free startup/import check must pass in an actual native sandbox before
configuring a provider. Image loading and import qualification dispatch no model request.

Keep gateway configuration, generated PKI, runtime JSON, policy files, logs and reports under
`.harness/openshell/private/` with mode `0700` for the directory and `0600` for private files.
Never commit client keys, gateway JWT keys, provider credentials or runtime receipts. Create
the dedicated daemon only inside the managed VM with the ownership-checked helper:

```bash
LIMA_VERSION="$(awk -F= '$1 == "LIMA_VERSION" {print $2}' .dev-tools/versions.env)"
CHECKOUT_ID="$(basename "$(cat .harness/runtime-home)")"
LIMA_HOME="$(cat .harness/runtime-home)" \
  ".harness/tools/lima-${LIMA_VERSION}/bin/limactl" shell --tty=false --workdir "$PWD" h \
  sudo --non-interactive python3 "$PWD/scripts/openshell_guest.py" start \
  --checkout-id "$CHECKOUT_ID"
```

The helper owns a separate Docker socket, data root and containerd namespace. It checks the
shared firewall, route and forwarding invariants. Use only this guest socket for OpenShell;
do not change the host Docker context or point OpenShell at the harness daemon. The dedicated
gateway uses the Docker driver's `socket_path`, `compute_driver = "docker"`, the pinned OCI
images, TLS with client authentication, and launch-scoped gateway JWT keys. The gateway process
is launched with the pinned binary, its private config, the Docker driver and mTLS auth enabled.
Run its configuration preflight before startup and independently inspect the guest process and
selected daemon socket afterward.

## Configuration contract

The private gateway TOML uses the v0.1.2 schema. Replace every path and digest placeholder
below with private generated files and manifest-pinned images; the placeholders are not active
credentials or deployment defaults.

```toml
[openshell]
version = 1

[openshell.gateway]
name = "checkout-openshell"
bind_address = "127.0.0.1"
health_bind_address = "127.0.0.1"
log_level = "info"
compute_driver = "docker"
disable_tls = false
guest_tls_ca = "/var/lib/ih-openshell/<checkout-id>/certs/ca.crt"
guest_tls_cert = "/var/lib/ih-openshell/<checkout-id>/certs/server.crt"
guest_tls_key = "/var/lib/ih-openshell/<checkout-id>/certs/server.key"

[openshell.gateway.tls]
cert_path = "/var/lib/ih-openshell/<checkout-id>/certs/server.crt"
key_path = "/var/lib/ih-openshell/<checkout-id>/certs/server.key"
client_ca_path = "/var/lib/ih-openshell/<checkout-id>/certs/ca.crt"

[openshell.gateway.gateway_jwt]
signing_key_path = "/var/lib/ih-openshell/<checkout-id>/certs/signing.pem"
public_key_path = "/var/lib/ih-openshell/<checkout-id>/certs/public.pem"
kid_path = "/var/lib/ih-openshell/<checkout-id>/certs/kid"

[openshell.drivers.docker]
socket_path = "/var/lib/ih-openshell/<checkout-id>/run/docker.sock"
sandbox_pids_limit = 256
default_image = "sha256:<workspace-image-id>"
sandbox_runtime_image = "<manifest-pinned-sandbox-image>@sha256:<digest>"
supervisor_image = "<manifest-pinned-supervisor-image>@sha256:<digest>"
image_pull_policy = "if_not_present"
sandbox_label = "<checkout-owned-label>"
grpc_endpoint = "<guest-local-gateway-address>"
```

Run the pinned gateway's configuration preflight before launch. Start the binary using this
private config, the Docker driver and mTLS authentication. Verify the guest PID belongs to that
exact binary/config invocation and independently verify the selected dedicated daemon socket.
Do not enable plaintext listeners or host Docker access.

`HARNESS_OPENSHELL_CONFIG` points to private JSON with the host-forwarded gRPC endpoint,
workspace, durable receipt directory, client mTLS paths, exact dedicated Docker
`inspection_socket` and read-only command, Lima home, observed supervisor image ID, and the
three profile definitions. Each profile has an immutable image digest, absolute policy path,
CPU and memory limits. Only the `model` profile may name a provider; `workspace` and `probe`
must not. This is the JSON contract consumed by the adapter:

```json
{
  "endpoint": "127.0.0.1:<forwarded-grpc-port>",
  "workspace": "default",
  "state_dir": "/absolute/private/openshell/receipts",
  "tls_ca": "/absolute/private/openshell/client-ca.crt",
  "tls_cert": "/absolute/private/openshell/client.crt",
  "tls_key": "/absolute/private/openshell/client.key",
  "inspection_socket": "unix:///var/lib/ih-openshell/<checkout-id>/run/docker.sock",
  "inspection_command": [
    "/absolute/path/to/limactl", "shell", "h", "sudo", "--non-interactive",
    "docker", "--host", "unix:///var/lib/ih-openshell/<checkout-id>/run/docker.sock"
  ],
  "inspection_lima_home": "/absolute/path/to/managed-lima-home",
  "supervisor_image": "sha256:<observed-image-id>",
  "profiles": {
    "workspace": {
      "image": "sha256:<workspace-image-id>",
      "policy": "/absolute/private/openshell/workspace-policy.yaml",
      "cpu": "1", "memory": "512Mi"
    },
    "probe": {
      "image": "sha256:<workspace-image-id>",
      "policy": "/absolute/private/openshell/probe-policy.yaml",
      "cpu": "1", "memory": "512Mi"
    },
    "model": {
      "image": "sha256:<model-executor-image-id>",
      "policy": "/absolute/private/openshell/model-policy.yaml",
      "cpu": "1", "memory": "512Mi",
      "provider": "<native-provider-name>"
    }
  }
}
```

Policies are authored operator configuration, not execution evidence. This minimal example
permits only the two exact Python package hosts; add other exact hosts and observed client
binary paths only for required toolchains. The qualified toolchain profile also allows
`/dev/null` as a write target because Maven and other tools use it. The adapter verifies that
it is the actual character device major 1, minor 3, opens it without following symlinks, and
confirms writes are discarded and reads return EOF; do not make `/dev` writable.

```yaml
version: 1
filesystem:
  include_workdir: false
  read_only: [/usr, /bin, /lib, /lib64, /etc, /proc, /sys/fs/cgroup]
  read_write: [/workspace, /tmp, /dev/null]
landlock:
  compatibility: hard_requirement
process:
  run_as_user: 65532
  run_as_group: 65532
network_policies:
  packages:
    binaries:
      - path: /usr/local/bin/python3.12
    endpoints:
      - host: pypi.org
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
          - allow: {method: GET, path: "/**"}
          - allow: {method: HEAD, path: "/**"}
      - host: files.pythonhosted.org
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
          - allow: {method: GET, path: "/**"}
          - allow: {method: HEAD, path: "/**"}
```

Omit TLS mode so native OpenShell automatically terminates HTTPS on port 443. Do not combine
`access` presets with explicit `rules`. The probe policy has the same filesystem and process
sections but no `network_policies`; it has no provider. The model profile has no repository
workspace and attaches only its explicitly configured native provider. Do not add wildcard
hosts or Docker registry access to workload egress.

OpenShell v0.1.2's Docker driver leaves the workload root filesystem writable. Qualification
therefore requires live Landlock discriminators: a successful write/delete in `/workspace`,
denial of writes to `/dev/shm`, and denial of a symlink escape from the workspace. The trusted
runtime also independently inspects exact native-owned workloads for pinned image, non-root
identity, dropped capabilities, seccomp, no-new-privileges, disabled network, bounded
CPU/memory/PIDs and absence of host bind mounts. A configured profile, sandbox name or gateway
`Ready` state alone is not proof.

## Qualification and evaluation

Full `./dev` runs native qualification. The direct command is useful after changing a policy,
image, adapter or runtime configuration:

```bash
uv run --locked harness qualify --output .harness/reports/native-review.json
```

Qualification must exercise workspace and fresh offline-probe creation, native policy
admission, upload, bounded execution and download, original-source verification, cleanup,
and replay of saved receipts. It records actual container properties and in-sandbox controls.
Preserve failed-run evidence privately; remove only resources whose native IDs and dedicated
daemon ownership have been corroborated.

Live model evaluation is a separate, explicitly authorized step. Configure the endpoint and
served model identifier in the worker environment, and put provider credentials only in the
native model provider. Run the unchanged registered corpus with:

```bash
uv run --locked harness eval --allow-inference --output .harness/reports/model-review.json
```

Review the manifest, endpoint, model, dataset hashes, report destination and bounded request
budget before dispatch. Setup, native qualification and deterministic tests make zero model
calls. See the [runtime architecture](../../docs/architecture/TRIAGE_SYSTEM.md) and the
[repository runbook](../../README.md) for the Temporal workflow and recovery boundaries.
