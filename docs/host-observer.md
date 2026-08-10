# Host-side network observer: design and implementation plan

## Status and decision

This document specifies the next gated capability: an independently operated
host-side collector that can attest to the two synthetic network flows used by
the Minikube policy/oracle lab. It does **not** authorize target-controlled
code, active validation, or general worker networking. Those are later,
separately approved capabilities.

The repository currently has a fail-closed *prototype contract* in
`host_observer.py`. It defines a signed envelope and checks that fresh allowed
and denied flows are bound to the synthetic experiment. It deliberately cannot
admit a worker on this host: the current user lacks BPF access and no external
collector supplies evidence.

The current prototype signs with HMAC. That is acceptable for deterministic
fixtures and local tamper detection, but not for the required signer/verifier
separation: any component able to verify with a shared HMAC key can also forge
an envelope. The implementation below therefore begins by replacing HMAC with
an asymmetric, versioned evidence format. Do not use the v1 HMAC format as a
production or independently operated attestation mechanism.

## Objective

For a fresh, controller-created synthetic experiment, independently establish
all of the following before permitting even a narrowly scoped future
network-capable synthetic worker:

1. An approved workload attempted the expected TCP flow to the exact synthetic
   oracle ClusterIP and port.
2. An allow decision reached the oracle and produced the fixed synthetic
   response.
3. A separately identified denied workload attempted the same destination and
   was blocked by the selected CNI/policy enforcement path.
4. A collector outside the Kubernetes workload and harness-controller trust
   boundaries observed the relevant events and signed a short-lived envelope.
5. The harness verified the envelope's signer, freshness, experiment binding,
   workload identities, destination, and policy-decision identities.

The existing direct-ClusterIP probes deliberately eliminate DNS as an
explanation for a deny result. The observer must still distinguish a policy
enforcement drop from an unrelated connection failure; a client-side timeout
or nonzero exit status alone is not evidence of a policy decision.

## Trust boundaries

```
 controller                      Minikube (Docker driver)       host observer
 ┌──────────────────────┐       ┌─────────────────────────┐    ┌────────────────────────┐
 │ creates experiment ID │──────▶│ allowed/denied probe Jobs │    │ root-managed service   │
 │ verifies public key   │       │ CNI policy + oracle       │◀──▶│ BPF / enforcement view │
 │ fail-closed admission │◀──────│ signed local lab record    │    │ owns private key       │
 └──────────────────────┘       └─────────────────────────┘    └────────────────────────┘
             ▲                                                               │
             └──────── signed metadata only; no payloads or source ─────────┘
```

The controller, probe jobs, oracle, and CNI manifests are not an independent
observer. A Kubernetes DaemonSet controlled by the same namespace/controller is
also insufficient. A host service can be operationally independent when it has
its own account, service definition, key, logs, and change authority. On one
machine, host root can ultimately subvert both the collector and controller,
so this is an administrative separation rather than a hard adversarial
boundary. A stronger deployment uses a separately administered node and/or an
external KMS/HSM-backed signing identity.

## Current-host feasibility

The current host is suitable for a constrained development deployment:

| Requirement | Current result | Action |
| --- | --- | --- |
| system service manager | systemd 255 | Install and supervise a dedicated collector unit. |
| kernel BPF support | Linux 6.17, BPF syscall/JIT/BTF/cgroups available | Use CO-RE/libbpf-based probes; no kernel rebuild is indicated. |
| BPF and trace mounts | `/sys/fs/bpf` and tracefs mounted | Keep mounts managed by the host; do not remount from a workload. |
| ordinary-user BPF access | unavailable; `kernel.unprivileged_bpf_disabled=2` | Keep this setting. Run only the collector with narrowly granted privilege. |
| administrative authority | passwordless `sudo` is available | An authorized operator can install the unit and provision its key. |
| Minikube topology | Docker driver and kindnet | Collector must understand the Minikube node container's network namespace and pod/container cgroups. |

The host must not grant broad BPF access to the normal harness account, turn on
unprivileged BPF, or run the collector inside an untrusted worker.

## Deployment model

### Service ownership

Create a dedicated, non-login `harness-observer` account. The service binary,
configuration, signing private key, and raw local diagnostic logs are owned by
root or that service account and are not writable by the harness controller,
Minikube workloads, Docker containers, or abox guests.

The service starts before a test run, performs a bounded health check, attaches
only approved collection programs, emits an attested heartbeat, and writes a
single signed evidence envelope per experiment. It should reject experiments
that lack a controller-generated nonce or cannot be mapped to an approved
synthetic workload identity.

The harness receives a copy of the signed envelope and a pinned public key. It
never receives the private signing key, raw BPF maps, packet payloads, or a
general query interface to the collector.

### Least privilege

Prefer a native, statically pinned collector with a narrow systemd service
profile. The final capability set depends on the exact attachment method, but
the expected starting point on this kernel is:

- `CAP_BPF` and `CAP_PERFMON` to load and attach the approved BPF programs;
- `CAP_NET_ADMIN` only when a TC or network-namespace attachment requires it;
- no general shell endpoint, package installation, Docker socket, Kubernetes
  credentials, cloud credentials, or controller/provider credentials.

Avoid `CAP_SYS_ADMIN` unless a specific, documented kernel/program operation
requires it and no narrower alternative exists. Bound the service's filesystem
write access to its state/log directory, require a read-only executable and
configuration, use a restrictive `CapabilityBoundingSet`, and set resource
limits for pinned maps, memory, CPU, and event rate. The unit must run with the
host network namespace; a private network namespace would hide the events it
is responsible for observing.

The service should have a documented upgrade procedure: stop collection,
verify the collector binary/configuration hashes, install the approved version,
start it, require a new signed heartbeat, and invalidate old evidence.

### Minikube Docker-driver correlation

Minikube's Docker driver does not provide a separate host kernel. Pods run
behind the Minikube node container's namespace and cgroup hierarchy, and CNI
enforcement happens within that topology. The collector must therefore:

1. identify the repository-wrapper-derived Minikube node/container and its network
   namespace without trusting a model-provided name or arbitrary PID;
2. enumerate only the approved synthetic namespace and its current probe job
   container/cgroup identities through trusted host/node runtime metadata;
3. bind each identity to the controller experiment nonce and an immutable
   workload ID, rather than to a mutable pod name alone;
4. observe the TCP attempt and the enforcement/allow outcome at the node/CNI
   layer; and
5. discard all flows outside the approved synthetic oracle destination.

This is the complex part of the local implementation. A generic host-wide
packet logger is neither necessary nor acceptable. In particular, evidence must
not rely solely on an oracle access log: it would not see denied traffic.

For a production cluster, use the same logical contract but deploy a
node-level collector operated independently of the application namespace. The
portable Kubernetes policy/oracle manifests remain useful; the Docker driver
itself must be replaced before hostile workload execution is considered.

## Collection and decision semantics

The first collector release supports only the existing synthetic TCP/8080
oracle experiment. It is not a general network-monitoring product.

For each approved experiment it should record two distinct facts for each
flow:

- **attempt:** an attributable workload initiated a TCP connection to the
  pinned direct ClusterIP/port; and
- **outcome:** either the oracle confirmed the allow path or the CNI/policy
  enforcement layer reported a deny/drop for that same attributable attempt.

The collector may combine appropriately scoped BPF probes with CNI enforcement
signals. Candidate mechanisms must be evaluated against the actual kindnet
version and host topology; the implementation must not claim that a connect
tracepoint alone proves an allow or deny. If the CNI cannot supply an
attributable policy decision signal, the experiment remains non-admitting and
the CNI/instrumentation choice must change.

`policy_decision_id` is an immutable, collector-derived identifier for the
enforcement observation. It is not a string supplied by a probe, the model, or
the controller. The collector should derive it from the approved policy digest,
the observed enforcement hook/rule identity, and a per-event identifier without
embedding raw packet content.

The collector must cap event counts, retain only the two expected flows for the
short experiment window, and report overflow or attribution ambiguity as an
unhealthy/indeterminate result. Indeterminate is a denial, not a retry that
silently admits work.

## Evidence contract v2

Replace the v1 HMAC `HostObserverEvidence` schema with an explicit version 2
envelope. Canonical JSON is serialized with sorted keys and compact separators,
then signed over the bytes excluding `signature`.

```json
{
  "schema_version": 2,
  "signature_algorithm": "ed25519",
  "key_id": "observer-dev-2026-08",
  "observer_id": "host-observer-dev-01",
  "observer_mode": "host-side",
  "collector_version": "0.1.0",
  "healthy": true,
  "collected_at": "2026-08-09T00:00:00Z",
  "experiment_id": "controller-generated-unique-nonce",
  "lab_identity": {
    "profile": "infosec-harness-<checkout-path-hash>",
    "minikube_version": "v1.38.1",
    "cni_identity": "kindnet:<pinned-identity>",
    "policy_digest": "sha256:<digest>"
  },
  "flows": [
    {
      "workload_id": "minikube:synthetic-probe:allowed:<immutable-id>",
      "verdict": "allowed",
      "protocol": "tcp",
      "destination_ip": "10.96.0.10",
      "destination_port": 8080,
      "attempt_id": "collector-generated-id",
      "policy_decision_id": "collector-derived-id",
      "observed_at": "2026-08-09T00:00:00Z"
    },
    {
      "workload_id": "minikube:synthetic-probe:denied:<immutable-id>",
      "verdict": "denied",
      "protocol": "tcp",
      "destination_ip": "10.96.0.10",
      "destination_port": 8080,
      "attempt_id": "collector-generated-id",
      "policy_decision_id": "collector-derived-id",
      "observed_at": "2026-08-09T00:00:00Z"
    }
  ],
  "signature": "base64url-ed25519-signature"
}
```

The final schema should also include a bounded collector-health summary (loaded
program version/hash, event-loss count, and attachment identity), but must not
contain packet payloads, domain-independent flow history, source content,
credentials, prompts, raw BPF-map dumps, environment variables, or model text.

Validation requirements:

- accept only known schema/signature algorithms and pinned `key_id` values;
- verify with the pinned public key before parsing any semantics as trusted;
- reject evidence older than two minutes, evidence from the future outside a
  small clock-skew allowance, or evidence reused for another experiment;
- require exactly one matching allowed and one matching denied flow in the
  first release; reject duplicate or ambiguous records;
- verify the experiment nonce, lab/CNI/policy identities, workloads,
  destination, port, and policy decision IDs against controller-collected
  experiment evidence; and
- record every rejection as an audit policy decision without persisting
  sensitive raw diagnostics.

Private keys are generated and stored by the observer operator. The harness
repository contains only an allowlisted public key/key ID (or a certificate
chain rooted in an operator-controlled trust anchor). Local development key
rotation is explicit: publish the new public key, pin both keys for a bounded
overlap, change the observer, verify a heartbeat, then remove the old key.

## Admission workflow

1. The controller creates an unpredictable experiment nonce and records the
   intended profile, CNI/policy digest, direct oracle ClusterIP, and immutable
   allowed/denied workload identities.
2. It starts the synthetic probes and saves the existing controller-side lab
   evidence.
3. The separately running observer sees only flows matching that nonce/window,
   creates a v2 envelope, and signs it with its private key.
4. The controller reads the signed envelope from a designated read-only handoff
   path and verifies it using the pinned public key.
5. `minikube-lab-admission` admits only if cluster readiness, default deny,
   oracle health, fresh local experiment evidence, and fresh independently
   signed observer evidence all agree. Any missing or contradictory input
   denies admission.
6. Admission applies only to the declared no-target-code synthetic capability.
   It does not mutate worker egress rules or start arbitrary commands.

The handoff should be atomic (write temporary file, fsync, rename), permissioned
so the controller cannot modify evidence, and retained only long enough for the
audit/reference policy. The controller should store the envelope's content hash
and verification result, not a raw collector log.

## Security and operational requirements

- The collector has no HTTP/RPC listener in the first release. It accepts only
  local, root-managed configuration and emits files to the handoff directory.
- The controller cannot choose arbitrary interfaces, PIDs, BPF programs,
  destinations, or collection filters. Its experiment request is a small,
  validated nonce/identity file or preconfigured watch set.
- Raw diagnostics remain root-only and are rate- and size-bounded. The signed
  handoff is metadata-only.
- Collector health is false on program attach failure, lost events, clock error,
  cgroup attribution ambiguity, unexpected CNI identity, unsupported protocol,
  or failed signature operation.
- The service's operational logs, unit changes, key rotation, and evidence
  verification failures require audit records. A controller failure cannot
  restart, reconfigure, or rekey the observer.
- Disable or remove the service when the synthetic lab is not in use; stale
  heartbeats/evidence must never satisfy admission.

## Implementation list

The list is ordered. A later item must not be started as an admission-enabling
change until its prerequisites and tests are complete.

### Phase 0 — lock the contract and trust model

- [ ] Add ADR-004 describing asymmetric observer attestation, single-host
  limitations, and the explicit non-goals above.
- [ ] Replace the v1 HMAC model with a versioned v2 Ed25519 model; reject v1
  for live admission while retaining only fixture migration support if needed.
- [ ] Add a small, pinned cryptographic implementation and dependency-admission
  record; do not add an agent, telemetry, or observability framework.
- [ ] Add canonical serialization, public-key/key-ID allowlisting, expiry,
  clock-skew, replay/nonce, duplicate-flow, and unknown-field tests.
- [ ] Change CLI options from `--observer-key` to an explicit
  `--observer-public-key`/trust-store input, with read-only safe-permission
  validation.

**Acceptance:** a valid Ed25519 fixture verifies; a fixture with a changed
payload, wrong key ID, stale time, reused nonce, missing denial, duplicate flow,
or HMAC-only v1 envelope fails closed and writes an audit policy decision.

### Phase 1 — define the synthetic identity handoff

- [ ] Add a controller-authored, bounded experiment-request file containing a
  random nonce, fixed expiry, Minikube profile/version/CNI/policy digests,
  direct ClusterIP/port, and the two immutable probe identities.
- [ ] Modify the oracle/probe setup to expose only those immutable identities
  through trusted Kubernetes/runtime metadata; do not accept model or pod-label
  text as an identity source.
- [ ] Bind the existing `SyntheticExperimentEvidence` to the same nonce and
  policy/CNI digests.
- [ ] Define root-owned request, handoff, raw-log, and public-key paths plus
  atomic-file semantics and retention limits.

**Acceptance:** controller and observer fixtures agree only for the exact fresh
experiment; changes to ClusterIP, profile, CNI identity, policy digest, or
workload identity reject admission.

### Phase 2 — collector proof of concept (non-admitting)

- [ ] Choose and document the minimal supported collector language/runtime
  (for example, a small pinned CO-RE/libbpf implementation); build it outside
  triage runs and record binary/source hashes.
- [ ] Implement read-only discovery of the Minikube node container/network
  namespace and the two synthetic probe cgroups.
- [ ] Attach approved probes that record TCP attempts for only the pinned
  ClusterIP/8080 and the two approved cgroups during the short experiment
  window.
- [ ] Measure lost events and cgroup/namespace attribution ambiguity; expose
  these only as bounded health counters.
- [ ] Add a dry-run mode that emits no evidence and cannot alter networking.

**Acceptance:** on this host the collector can attribute both synthetic probe
attempts without collecting unrelated payloads or flows. It remains
non-admitting until Phase 3 proves enforcement outcomes.

### Phase 3 — policy outcome correlation (non-admitting until proven)

- [ ] Inspect the pinned kindnet enforcement mechanism and select a narrowly
  scoped enforcement/drop signal that can be correlated with a recorded
  attempted flow.
- [ ] Implement allowed-oracle confirmation and denied enforcement correlation
  using collector-generated attempt and policy-decision IDs.
- [ ] Treat unavailable CNI decision data, ambiguous correlation, and event
  loss as unhealthy/indeterminate.
- [ ] Add a controlled negative case where the policy is intentionally changed
  or the expected deny is absent; verify the collector never labels it denied.

**Acceptance:** an allowed probe produces an attributable allow record, a
denied probe produces an attributable enforcement record, and connection errors
without enforcement evidence cannot satisfy the deny requirement.

### Phase 4 — host service hardening

- [ ] Create the dedicated system user, root-owned directories, key-generation
  procedure, public-key distribution procedure, and least-capability systemd
  unit.
- [ ] Pin collector binary/configuration hashes and add startup self-tests for
  BPF availability, required attachment locations, key readability, and CNI
  identity.
- [ ] Configure bounded logs/maps/events, atomic signed-handoff writes, service
  restart policy, health heartbeat, and auditable upgrade/rotation procedures.
- [ ] Have a separate operator review the service unit, capabilities, binary
  provenance, and data minimization before enabling the gate.

**Acceptance:** the controller account cannot alter the unit, private key,
raw logs, or emitted envelope; restart, key failure, attach failure, and event
loss all make observer health false.

### Phase 5 — controller admission integration

- [ ] Make `minikube-lab-status` derive observer health from verified v2
  evidence rather than its current intentional `unavailable` value.
- [ ] Update `minikube-lab-admission` to validate the experiment request,
  controller-side lab evidence, observer evidence, and trust store together.
- [ ] Preserve all denial reason codes in JSONL, SQLite, and the report without
  exposing raw collector data.
- [ ] Add deterministic fixtures for valid evidence, bad signature, stale
  evidence, wrong nonce, wrong destination, wrong workload, missing allow,
  missing deny, duplicate flow, unhealthy collector, and unknown key ID.

**Acceptance:** `just minikube-lab-admission` admits only the fully matching
synthetic experiment. Every altered/missing input returns a distinct, recorded
non-admission result.

### Phase 6 — live validation and operational readiness

- [ ] Run the positive allowed/denied experiment repeatedly with fresh nonces;
  record only content hashes and summaries in the repository-managed audit.
- [ ] Execute failure-injection tests for observer stop, forced event loss,
  expired key, stale evidence, CNI identity drift, altered policy, and
  controller/collector handoff permission errors.
- [ ] Review raw logs for data minimization and verify no secret/source/payload
  material reaches reports, SQLite summaries, JSONL, or model inputs.
- [ ] Document the separately administered-node/KMS path before claiming a
  production-strength independence boundary.

**Acceptance:** all positive runs contain exactly the expected signed records;
all failure injections fail closed; no test enables arbitrary target-code
execution or generic worker egress.

## Explicitly deferred after this plan

- Network access for target-controlled code.
- Active validation against repositories, external services, or user-supplied
  endpoints.
- General packet capture, flow export, or a collector API.
- Treating Minikube's Docker driver as a hostile-code isolation boundary.
- Claiming independent attestation from a single machine controlled by one root
  administrator.

The next smallest safe engineering change is Phase 0: asymmetric v2 evidence
and its fail-closed unit/CLI tests. It improves the trust contract without
granting host privileges or enabling any network-capable worker.
