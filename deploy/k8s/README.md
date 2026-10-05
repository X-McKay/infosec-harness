# Kubernetes sandbox specification

Applies the isolated namespace where probe Pods run:

```bash
kubectl apply -f deploy/k8s/sandbox-namespace.yaml
```

- `RuntimeClass gvisor` (handler `runsc`) — every probe Pod sets `runtimeClassName: gvisor`.
- `NetworkPolicy default-deny-all` — no ingress/egress for sandbox Pods (probes have no
  network; the CNI must enforce NetworkPolicy, e.g. Cilium/Calico).
- `automountServiceAccountToken: false` and the restricted Pod Security Standard.

The worker executes through the Docker runner. These manifests are deployment building blocks,
not an implemented Kubernetes runner.
A RuntimeClass name alone is not execution evidence; a future runner must verify real isolation,
CNI policy enforcement, artifact handling and durable retry/cancellation before operational use.


## Control plane with hosted services

[control-plane](control-plane/) contains a separate operator template for the API and a
Temporal worker using hosted PostgreSQL, Temporal and S3. It does not install those servers.
The API is a ClusterIP service, intended for an authenticated internal gateway; no public
Ingress is supplied. Runtime configuration is shared through a ConfigMap and a Secret,
with optional mounted CA/client certificates. The image must be replaced with your immutable
backend build before deploying. Never put database URLs, API keys or private keys in ConfigMaps.

1. Copy the template to an operator-owned deployment directory. Replace Temporal address,
   namespace, queue, artifact bucket/region and image with the environment's actual values.
   Run `kubectl kustomize <directory>` to inspect the resulting manifest.
2. Create namespace `harness-control`. Supply `harness-service-credentials` from a private env
   file containing `HARNESS_DATABASE_URL` and, for Temporal API-key authentication,
   `HARNESS_TEMPORAL_API_KEY`. For mTLS, omit the API key and supply
   `HARNESS_TEMPORAL_TLS_CLIENT_CERT` and `HARNESS_TEMPORAL_TLS_CLIENT_KEY` paths. Mount their
   files in `harness-service-tls`; custom PostgreSQL/Temporal CA paths use the same Secret.
   Public system roots need no custom CA Secret. Certificate/key pairs must be complete.
3. Run the existing `harness migrate` command once using the same image, service ConfigMap,
   credentials and TLS mounts to initialize/update the application schema. This does not
   provision Temporal or move data between environments. Then apply the reviewed template.
4. Start with stub models (`HARNESS_MODEL_MODE=stub`). Verify API/database access and a fresh
   Temporal workflow against the chosen namespace before enabling live models.

API and worker use the same Temporal connector, including verified TLS and API keys or mTLS.
AWS S3 uses workload identity/default credential discovery; attach the appropriate identity
for `harness` with your cluster's provider integration. If that integration requires a projected
service-account token, add its explicitly scoped token projection; general automatic API
credentials are disabled. Temporary static credentials can use access/secret/session-token
fields in the service Secret. Hosted S3 buckets are pre-created (`HARNESS_S3_CREATE_BUCKET=false`).

### Worker executor requirement

The template keeps worker replicas at **zero** until a real executor is connected and tested.
The current worker executes Docker builds/probes. Running that worker process in Kubernetes
does not turn it into a Kubernetes Job runner.

To activate the supplied Docker-backed worker, provide all three operator-owned resources:

- `harness-executor` ConfigMap: `DOCKER_HOST` pointing at a dedicated TLS Docker endpoint,
  plus `HARNESS_BUILDX_BUILDER`, `HARNESS_BUILD_EGRESS_PROXY`,
  `HARNESS_BUILD_EGRESS_HOST_IP` and `HARNESS_BUILD_EGRESS_NETWORK` for its verified
  runsc/build-egress setup. The proxy address must be usable in that executor's network.
- `harness-docker-tls` Secret containing Docker's `ca.pem`, `cert.pem` and `key.pem`.
  The worker sets `DOCKER_TLS_VERIFY=1`; the template grants no privileged Pod or host socket.
- `harness-worker-workspace` PVC accessible to the dedicated daemon at **the same absolute
  `/workspace` path**. Build contexts, snapshots and probe bind mounts must be daemon-visible.
  `TMPDIR=/workspace` keeps temporary build inputs on that shared filesystem. Provision the
  daemon-side mount explicitly; a worker PVC alone does not establish that visibility.

Verify the existing actual runsc/build-egress fixtures from the worker environment, plus
artifact roundtrips and a stub production workflow, before scaling `harness-worker` to one.
Scale beyond one only after workspace/image/cache ownership has been qualified. A missing
executor stays fail-closed. Hosted control-plane connection support is implemented; this
repository does not claim an executed Kubernetes deployment or native Kubernetes probe runner.

For opt-in OpenShell inference, mount only the worker catalog and its controller authentication
material into the worker. Run the privileged native controller/executor infrastructure in its
own qualified trust boundary, as described in the [broker runbook](../../docs/broker/RUNBOOK.md).
Provider tokens, gateway authority and Docker administrator credentials never belong in
untrusted inference executors or probe containers.
