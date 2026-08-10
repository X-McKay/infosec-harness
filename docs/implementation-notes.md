# Implementation notes

## ADR-001: controller-only no-exec vertical slice

The first end-to-end workflow uses controller-owned bounded file reads and never starts
a target worker. This keeps the trusted core reviewable and avoids a misleading claim
that a local container alone proves safe execution. `NoExecSandbox.execute()` refuses
work by design. Networked workers are fail-closed until a host-side observer is present.

## ADR-002: replay before live providers

Replay fixtures contain only visible structured output, fixed usage, and replay
provenance. They provide deterministic SARIF-to-report testing without credentials or
network access. Native provider imports are lazy and optional; they never participate in
the default command path.

## ADR-003: abox microVM worker; Minikube synthetic oracle

`AboxWorkerPlan` is the only current microVM worker contract. It opens a bounded regular
input with `O_NOFOLLOW`, snapshots its bytes once before a guest exists, forces `safe`
network mode and `--ephemeral`, disables environment warming, and uses a fixed guest
digest program. It revalidates the approved abox configuration and records the abox
version and controller-workspace commit. It cannot receive a target command or a target
repository. Its live self-test uses a temporary controller-owned Git workspace because
abox requires a worktree; the private snapshot is mounted through abox's read-only input
channel.

`infra/kubernetes/base` is the portable policy/oracle base and `infra/minikube` is a
thin local overlay. The base's pinned non-root responder and direct-ClusterIP probes
prove one intended allow and one intended deny, then save a locally signed experiment
record with manifest hashes, CNI identity and log artifacts. This demonstrates CNI
enforcement only. The Minikube Docker driver shares the host kernel, and neither
Kubernetes NetworkPolicy nor abox's policy proxy is an independent flow observer.
`HostObserverEvidence` defines the separate signed collector contract: a real collector
must bind fresh allowed and denied flows to the workload ID, experiment, destination and
policy decisions before a network-capable worker can be admitted.

## ADR-004 (proposed): asymmetric host-observer attestation

The checked-in HMAC observer envelope is a deterministic prototype, not a deployment
attestation format: a shared verifier key can also forge evidence. Before any live
observer can satisfy admission, replace it with versioned Ed25519 evidence, where the
separately operated collector owns the private key and the controller has only a pinned
public key. The complete threat model, current-host constraints, data-minimization rules,
and phased implementation/acceptance list are in [host-observer.md](host-observer.md).
