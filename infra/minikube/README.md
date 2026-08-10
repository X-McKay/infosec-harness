# Local Minikube synthetic lab

This profile is only for the controller-owned no-exec worker and synthetic fixtures.
It uses Minikube's Docker driver, so it shares the host kernel and is **not** an
approved boundary for hostile target-controlled code or high-risk benchmarks.

## Local configuration isolation

Never run bare `kubectl` or bare `minikube` for this lab. The repository wrapper
creates a path-derived Minikube profile and stores its complete Minikube state under
the ignored `.harness/minikube/` directory:

- `.harness/minikube/kubeconfig` is the sole kubeconfig used by lab commands;
- `.harness/minikube/home/` is `MINIKUBE_HOME`, so profiles, certificates, and cache
  state do not use `~/.minikube`;
- the profile name includes a hash of this checkout's physical path, preventing a
  Docker-driver profile/container collision with another checkout; and
- every wrapper `kubectl` call passes both that kubeconfig and that context explicitly.

Inspect the effective local values with:

```bash
just minikube-lab-context
```

For an isolated diagnostic command, use the wrapper rather than the host default:

```bash
just minikube-lab-kubectl get namespaces
```

The experiment recorder refuses to call `kubectl` without one explicit absolute
`KUBECONFIG`; `just minikube-lab-record-experiment` supplies the repository-specific
one. This prevents an accidental read from or write to the host's normal kubeconfig.
The Docker daemon remains a shared host service, so this isolation does not make the
Docker-driver cluster a hostile-workload boundary.

`default-deny.yaml` establishes workload policy intent. The bootstrap self-test must
also prove the deployed CNI actually enforces egress policy before the harness admits a
worker. The observer is deliberately not deployed until its host/cgroup visibility and
integrity are independently validated; a Kubernetes NetworkPolicy is enforcement, not
independent observation.

`../kubernetes/base/oracle.yaml` defines a pinned, non-root synthetic HTTP responder.
`../kubernetes/probes/oracle-probes.yaml` contains an allowed client and a denied client.
Both use the oracle Service's direct ClusterIP, so the denied outcome cannot be explained
by DNS failure. Run `just minikube-lab-oracle` after bootstrap: success means the
approved probe received the fixed response while the denied probe could not. It saves a
locally signed experiment record under `.harness/minikube-lab/`. This verifies CNI
behavior for this synthetic experiment only; it does not change network-worker admission.

`just minikube-lab-status-json` collects the deployed namespace, policy, oracle and
probe state. `just minikube-lab-admission` consumes that live status and should currently
deny specifically because `observer_mode` is `unavailable`.

The production-shaped separation is deliberate: abox microVMs are the candidate worker
boundary, and this Kubernetes profile is the candidate policy/oracle plane. A later
cluster deployment can consume `../kubernetes/base`, retain these namespace, service and
policy manifests, and add an overlay for a separately attested host/node observer. It
must replace the local Minikube Docker driver before any hostile workload is considered.

Install Minikube v1.38.1 through the approved bootstrap path, verifying the official
Linux AMD64 SHA-256 `099477eaf248bcb5bcea8ce78a2898e93ac01461c35189da1848c3de82ecd22e`.
`just minikube-lab-bootstrap` refuses any other Minikube version and pins Kubernetes
v1.35.1 with the `kindnet` CNI. `mise.toml` pins the matching kubectl v1.35.1 client.
