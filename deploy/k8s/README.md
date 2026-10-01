# Kubernetes sandbox specification

Applies the isolated namespace where probe Pods run:

```bash
kubectl apply -f deploy/k8s/sandbox-namespace.yaml
```

- `RuntimeClass gvisor` (handler `runsc`) — every probe Pod sets `runtimeClassName: gvisor`.
- `NetworkPolicy default-deny-all` — no ingress/egress for sandbox Pods (probes have no
  network; the CNI must enforce NetworkPolicy, e.g. Cilium/Calico).
- `automountServiceAccountToken: false` and the restricted Pod Security Standard.

`infosec_harness.sandbox.k8s.render_probe_pod` renders a hardened Pod specification and is
unit-tested. It does not submit Pods, and the worker currently executes through the Docker
runner. These manifests are deployment building blocks, not an implemented Kubernetes runner.
A RuntimeClass name alone is not execution evidence; a future runner must verify real isolation,
CNI policy enforcement, artifact handling and durable retry/cancellation before operational use.
