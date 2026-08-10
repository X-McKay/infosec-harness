# Infosec Harness

This is a local, CLI-first Python 3.12 harness for authorized, read-only SARIF triage.
Its first release is deliberately small: it imports scanner findings, constructs bounded
source evidence, asks a validated replay/fake/provider adapter for a typed disposition,
and saves reproducible local evidence and reports. It does not execute repository code,
perform active validation, make external writes, or start a networked worker.

## Quick start

Prerequisites are Python 3.12, [`mise`](https://mise.jdx.dev/), `uv`, and `just`.
Trust the checked-in runtime declaration once, then bootstrap the pinned lockfile:

```bash
mise trust mise.toml
just bootstrap
just check
just test
just policy-self-test
just sandbox-self-test
just abox-worker-plan fixtures/replay/sample.json
just abox-worker-live-self-test fixtures/replay/sample.json
just network-self-test
just benchmark-self-test
just benchmark-dry-run harness-fixture-sarif-v1
just evaluate-replay
just context-self-test
just diff-review fixtures/sample-repo src/app_before.py src/app.py
```

The final self-test succeeds when it reports `observer_unavailable` and
`fail_closed: true`: this machine has no independently verifiable host-side flow
observer, so the harness explicitly prohibits network-enabled workers. That is a
capability gap, not an assertion that a rootless container is sufficient isolation.

## MicroVM worker and Kubernetes oracle lab

The abox integration is intentionally narrower than a target-execution backend. It
creates an ephemeral Cloud Hypervisor microVM in `safe` network mode, stages one sealed
controller artifact read-only, and runs a fixed SHA-256 verifier. The controller opens
the input without following links, snapshots its bounded bytes before launch, and
attests the abox version, workspace commit, and approved configuration hash. It never
accepts a target command or mounts a target repository. The live self-test builds a temporary,
controller-owned Git workspace because abox worktree isolation requires Git; it is
automatically removed after the test.

```bash
abox project validate
just abox-worker-live-self-test fixtures/replay/sample.json
```

Minikube remains the deployment-shaped synthetic policy/oracle plane, not the worker
isolation boundary. It has a pinned non-root oracle, default-deny policy, one explicitly
allowed probe, and one denied probe. The probe command succeeds only if those opposite
outcomes occur:

```bash
just minikube-lab-bootstrap
just minikube-lab-oracle
```

These commands never use `~/.kube/config` or `~/.minikube`: the repository wrapper
uses an ignored, checkout-specific profile and kubeconfig under `.harness/minikube/`.
Use `just minikube-lab-context` to inspect it and `just minikube-lab-kubectl …` for
an explicitly isolated diagnostic command. See the [local Minikube guide](infra/minikube/README.md)
for the isolation boundary and Docker-driver limitation.

This establishes that the selected CNI enforces the experiment's policy, but it does
not establish independently observed network truth. Each successful experiment writes a
locally HMAC-signed record under `.harness/minikube-lab/`, with the CNI identity, direct
Service ClusterIP, Job UIDs, manifest hashes, and redacted log artifact hashes.
`minikube-lab-admission` therefore
continues to deny a network-capable worker until signed host-side observer evidence is
available.

Run the deterministic, credential-free demonstration:

```bash
just triage fixtures/sample.sarif fixtures/sample-repo fixture-revision-001 --backend replay
# RUN_ID=run-f8b2a5ac4d00b308
# TERMINAL_STATE=complete

just report run-f8b2a5ac4d00b308
just cost-report run-f8b2a5ac4d00b308
```

The exact ID is content-derived; if a fixture changes, use the `RUN_ID` printed by
the triage command. The report includes imported scanner provenance, cited source
locations, supporting/counter evidence counts or proof gaps, a typed disposition,
replay model provenance, policy decisions, coverage/deferred surfaces, safety posture,
and token/cost accounting.

Every triage command also validates a signed, expiring authorization manifest before
collecting evidence. The demonstration uses `fixtures/authorization.json`; pass a
different controller-authored manifest with `--authorization path/to/manifest.json`.
Wrong revision, repository scope, expiry, signature, or missing read authority records
the separate terminal state `authorization_failed`.

Local run records are written under `.harness/`:

- `runs.sqlite3` is the queryable run metadata record.
- `audit.jsonl` is append-only controller audit evidence.
- `artifacts/sha256...` contains redacted content-addressed metadata/results;
  `artifacts/protected/sha256...` holds the minimum source-bearing request body needed
  for replay. Detected credential-like content stops ordinary tool collection rather
  than being sent to a model or report.

`just sbom` emits the minimal runtime dependency admission record. `uv.lock` is part
of the dependency closure and triage never invokes package, image, scanner, or plugin
installation.

`evals/benchmark-registry.json` is a small, fail-closed evaluation registry. It admits
only approved, pinned regression entries with oracle and known-clean evidence; it does
not put Inspect, benchmark images, or hidden graders on the normal triage import path.
`benchmark-dry-run` validates one registry entry and prints its immutable digests; it
does not fetch, materialize, or execute a task. The replay-only environment contract
and the first three candidate experiments are in [evaluation-experiments.md](docs/evaluation-experiments.md).
`just compare-runs RUN_A RUN_B` compares immutable run metadata without changing either
record. `just retention-audit` reports artifact/report counts only; it never deletes
data. `diff-review` emits a bounded, redacted unified diff and deferred proof gaps,
without running repository code.

## Design and safeguards

The trusted core is standard-library Python plus Pydantic. The controller owns policy,
canonical path checks, budgets, persistence, reports, and state transitions. Repository
files, SARIF messages, model output, and tool output are untrusted data. The source tool
catalog is currently limited to bounded canonicalized file reads used to construct an
`EvidenceSlice`; it never runs a model-authored command or shell string.

The state machine is fixed: `created → preflighted → planned → investigating →
adjudicating → review_required → complete`, with separate terminal outcomes for malformed
model output, provider refusal, policy denial, budget/timeout exhaustion, infrastructure
failure, cancellation, and restricted evidence. A high/critical false-positive proposal
is always marked human-review-required; this release cannot close or suppress a finding.

`ModelBackend` is small and provider-neutral. Replay and fake implementations cover
normal tests. The optional native OpenAI and Anthropic adapters use direct SDK imports
only when explicitly selected, preserve normalized usage/request identity, and do not
store hidden reasoning. Live tests are intentionally absent until an approved provider
and data-class policy is configured.

The default `NoExecSandbox` refuses all target-code execution. Controller-side reads
therefore need no target worker, provider credentials, home mount, engine socket, or
network interface. Signed `EgressPolicy` and `NetworkEvidence` models exist now; an
independent observer is required before any network-enabled or active-validation worker
can be admitted. Active validation, OCI/microVM target execution, enterprise context
connectors, plugins/MCP, RAG, queues, web UI, and model training are explicitly out of
scope.

## Failure demonstrations

The regression suite proves these terminal outcomes and checks that each is saved in
SQLite and JSONL rather than reported as success:

```bash
uv run infosec-harness triage fixtures/sample.sarif fixtures/sample-repo fixture-revision-001 \
  --backend replay --replay-fixture fixtures/replay/malformed.json
uv run infosec-harness triage fixtures/sample.sarif fixtures/sample-repo fixture-revision-001 \
  --backend replay --replay-fixture fixtures/replay/refusal.json
uv run infosec-harness triage fixtures/sample.sarif fixtures/sample-repo fixture-revision-001 \
  --backend replay --deny-tool-path ../outside
```

Timeout/budget exhaustion and sandbox/network-observer failures are injected by the
same deterministic unit/integration tests; see `tests/test_harness.py`. The network
self-test records the observer failure as a fail-closed non-admission outcome, while
the no-exec sandbox self-test proves execution is refused.

## Implementation notes and next gate

The initial architecture follows the bounded-evidence pipeline in the repository
research: no ambient model authority, minimal evidence views, immutable hashes,
explicit proof gaps, and human review. Reports are reproducible from SQLite plus their
referenced fixture/artifact hashes; replay makes no provider call.

The next smallest safe step is to install a privileged, independently operated host-side
collector that emits the checked-in observer-evidence contract. It must sign fresh
allowed and denied flows bound to the workload identity, experiment, destination, and
policy-decision IDs. The pinned no-network abox worker and Kubernetes oracle are now
present, but they do not authorize target-controlled execution. Only after that
admission gate should the project consider active validation in a separately approved
stronger-isolation environment.

`just observer-self-test` reports whether the current account can inspect host BPF state.
It remains non-admitting even when inspection is available: only a separately operated
collector's signed evidence may satisfy the observer gate. The proposed trust model,
current-host deployment constraints, evidence replacement, and sequenced implementation
work are documented in [host-observer.md](docs/host-observer.md).
