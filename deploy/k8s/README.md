# Kubernetes sandbox (phase 5)

Applies the isolated namespace where probe Pods run:

```bash
kubectl apply -f deploy/k8s/sandbox-namespace.yaml
```

- `RuntimeClass gvisor` (handler `runsc`) — every probe Pod sets `runtimeClassName: gvisor`.
- `NetworkPolicy default-deny-all` — no ingress/egress for sandbox Pods (probes have no
  network; the CNI must enforce NetworkPolicy, e.g. Cilium/Calico).
- `automountServiceAccountToken: false` and the restricted Pod Security Standard.

The worker renders each probe Pod with `infosec_harness.sandbox.k8s.render_probe_pod`
(non-root uid 10001, read-only root, dropped capabilities, tmpfs work dirs, resource
limits, `activeDeadlineSeconds`) and submits it via the in-cluster API. The **build** step
runs on a rootless BuildKit builder whose buildkitd runs under gVisor; build egress is
pinned to the repo-derived allowlist through the egress proxy (see docker-compose for the
local equivalent).
