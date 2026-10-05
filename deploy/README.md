# Deployment

The local compose stack contains PostgreSQL for Temporal, Temporal, its UI, the harness
API and the React UI. The allowlisted proxy is used by the trusted image builder.
There is no application database, object store, credential broker or second agent runtime.

The trusted worker runs separately with `harness worker` and an explicit OpenShell runtime
configuration. See [OpenShell provisioning](openshell/README.md). Its source snapshots and
command receipts require durable storage; do not launch replicas with independent copies
of that state. Temporal replay alone cannot recover an unrecorded external effect.

Service ports bind loopback. Remote deployment requires authenticated ingress, Temporal
TLS/authentication, mTLS to the OpenShell gateway, native provider configuration and durable
worker state. Secrets belong in operator-managed files or native provider configuration,
not committed compose variables. The local compose stack is not a production deployment.

The `investigate-v9` task queue is incompatible with old staged workflows. Drain older
queues before replacement. `harness qualify` proves actual runtime behavior; API health
only checks Temporal connectivity. Run live evaluation separately against the chosen model.
