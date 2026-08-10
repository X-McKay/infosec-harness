# Proposal 2: Controlled Multi-Team Service

## Summary

Turn the bounded pipeline into an internal service with centralized authentication,
policy, provider credentials, budgets, durable jobs, shared isolated workers, and
review workflows. Keep the same domain contracts and deterministic state machine from
Proposal 1. Distribution solves operational needs; it does not justify more model
autonomy.

Choose this proposal when the harness has demonstrated value and multiple teams need a
reliable governed service.

## Intended deployment

- Several AppSec/product-security teams and repository owners.
- Hundreds of scans or many thousands of finding triage decisions per week.
- Durable jobs, centralized audit/retention, organizational quotas, and reviewer
  assignment.
- Mixed providers and data classifications.
- Internal service only, behind enterprise identity and network controls.

## Architecture

```text
CLI / CI client / review UI
          |
      OIDC API
          |
 authorization + policy + job state ---- PostgreSQL
          |                                  |
   context broker -> claim snapshots ----- object storage
          |
      scheduler/leases                   audit/outbox
          |
   worker pools by trust class ---------- object storage
      |            |
read-only       validation
sandboxes       worker guests -> sealed target ranges
      |
provider broker/gateway -> OpenAI / Anthropic / approved providers
      |
redacted telemetry -> internal OpenTelemetry backend

Independent evaluation workers -> Inspect suites -> evaluation store
```

Use PostgreSQL as both source of truth and initial job queue through leased rows and
`FOR UPDATE SKIP LOCKED`. This avoids a second distributed system until measured
throughput requires one. Use transactional outbox events for audit and notifications.

## Service boundaries

### API and identity

A small FastAPI service accepts signed authorization manifests, immutable target
references, workflow configs, and review decisions. OIDC identities map to tenants,
repositories, roles, and budget scopes. Service accounts for CI have narrower rights
than human reviewers.

The API never accepts arbitrary provider credentials, container images, commands, or
network destinations from ordinary callers. Those are administrator-managed catalogs.

### Scheduler

The scheduler validates prerequisites, allocates stage budgets, chooses a worker trust
class, and issues a short-lived lease. It applies admission control by tenant,
repository sensitivity, provider quota, and total cost exposure. Idempotency keys make
retries safe.

Before active validation, the scheduler requires a fresh signed target manifest built
from the context broker, an immutable validation plan, a compatible range profile, and
all risk-class approvals. Ambiguous production status, target identity, ownership,
data class, downstream side effects, or environment drift fails closed.

### Context broker

Source-specific workers use tenant-scoped read-only identities to collect catalog,
cloud/Kubernetes, IAM, API/data, SBOM/provenance, aggregate telemetry, control, and
owner-approved business facts. They execute reviewed typed queries, not model-authored
SQL, cloud commands, or log searches. The broker stores bitemporal claims and coverage
gaps, preserves source conflicts, applies redaction/classification, and materializes a
minimal content-addressed `SecurityContextBundle` for each job.

The model, provider broker, and target workers never receive connector credentials.
Authorization filtering happens before retrieval, cache keys include tenant and
classification, and raw logs/tickets remain outside prompts unless a policy-approved
bounded excerpt answers a declared question.

### Workers

Workers are replaceable and have no long-lived provider credentials. They exchange a
workload identity for a task-scoped provider/broker token. Separate pools handle:

- read-only inventory/discovery;
- dependency acquisition with restricted egress;
- writable validation;
- higher-risk proof generation;
- public benchmark evaluation.

Validation pools are two-sided. A disposable worker guest reaches only a separately
isolated synthetic target range. Out-of-band policy, health monitoring, immutable
evidence, and the kill switch remain unreachable from both. The range contains local
identity, storage, queue, notification, payment, webhook, DNS, and callback fakes and
has no production, corporate, metadata, or public Internet route.

Do not schedule proprietary code and public untrusted benchmark images on the same
long-lived worker without reimaging and a proven isolation boundary.

### Provider broker

The broker enforces model allowlists, endpoint/data-retention policy, per-tenant
budgets, concurrency, request metadata, and usage accounting. Two implementation
choices are viable:

1. Extend the native adapter service from Proposal 1. This keeps the smallest
   dependency and behavior surface.
2. Deploy a pinned, reviewed LiteLLM gateway behind the harness adapters when virtual
   keys, broad provider coverage, and shared routing outweigh the extra service and
   supply-chain cost.

The domain layer still calls its own `ModelBackend`; it does not depend directly on a
gateway's OpenAI-compatible wire format. Provider-native features require declared
capabilities and conformance tests.

### Storage

PostgreSQL stores authoritative metadata and workflow state. An internal S3-compatible
store holds encrypted, content-addressed artifacts under per-tenant keys and retention
policies. Audit events are append-only and exported through a transactional outbox.
Vulnerability evidence never enters general application logs.

### Review UI

The UI is deliberately a workbench, not a chat interface. It shows the original
finding, supporting and contrary evidence, target revision, validation results, proof
gaps, model/tool provenance, spend, and disposition history. Reviewers can confirm,
return for evidence, mark inconclusive, or dismiss with a reason code. High-impact
actions require step-up authentication or two-person review according to policy.

Once confirmed, a finding moves through a separate remediation record: proposed patch,
security and regression-test evidence, owner review, deployment artifact, and
post-deploy verification. The service measures time from validated finding to verified
remediation rather than rewarding report volume alone.

## Policy model

Central policy evaluates:

- who may scan which repository/revision for which purpose;
- allowed tool and sandbox profiles;
- provider and endpoint eligibility by data classification;
- maximum cost, concurrency, attempts, and wall time;
- which actions require human or two-person approval;
- retention and export destinations;
- whether a finding can be auto-routed, never whether a high-impact finding is true.

For validation it also evaluates the signed rules-of-engagement and plan digest,
canonical target IDs, artifact digest, environment, action-catalog entries, target and
DNS/IP scope, synthetic identities/data, resource and impact budgets, oracle, health
abort conditions, approval window, and teardown policy. Plans are immutable; a scope
change requires new approval.

Implement policy as deterministic, versioned, unit-tested rules. A dedicated policy
engine can be introduced if the organization already operates one, but the model never
calls it directly and policy input excludes model-authored identity/scope fields.

## Security posture

Proposal 2 adds multi-tenant threats to the baseline:

- cross-tenant artifact, cache, trace, or database access;
- confused-deputy authorization through CI identities;
- SSRF and metadata access from workers;
- provider-key theft from a shared service;
- malicious container images and dependency caches;
- queue starvation and intentional cost exhaustion;
- reviewer phishing through finding content;
- unsafe export to tickets, chat, or source control.

Controls include tenant-scoped encryption and row-level authorization, short-lived
workload identities, signed work leases, image digest allowlists and signatures,
separate worker pools, default-deny egress, network proxy logs, per-tenant cache keys,
backpressure, reservation-based budgets, safe rendering of untrusted text, and an
export service that rechecks policy and redacts content.

Container isolation is acceptable for ordinary source review when hardened and
continuously tested. Higher-risk proof execution gets gVisor/Kata/microVM workers or is
rejected. No workload can access the orchestrator or container runtime socket.

## Cost strategy

Centralization enables a policy-driven model cascade:

```text
deterministic filter
  -> routine model
     -> accept supported low-risk disposition OR abstain
        -> strong model for uncertainty/high impact
           -> independent verifier for consequential cases
```

The scheduler reserves worst-case cost before starting, releases unused reservation,
and stops stages at their caps. Organization, tenant, repository, workflow, and run
budgets compose; the narrowest remaining limit wins.

Add:

- content-addressed repository maps and scanner result caches, tenant scoped;
- sanitized stable-prefix caching where current provider terms allow;
- overnight batch lanes for non-urgent eligible triage/evals;
- model/effort routing promoted only by paired internal evals;
- spend anomaly alerts and circuit breakers;
- chargeback/showback for repository owners;
- marginal-value reports for extra attempts and second-provider verification.

Do not silently route to a cheaper provider whose retention or cyber-policy behavior
is not approved for the target.

## Evaluation and release

Run evaluation in separate workers and accounts from production. The evaluation
registry pins task code, dataset/snapshot hashes, sandbox images, prompt/policy
versions, model IDs, grader versions, and budgets. Store multiple trials and bootstrap
confidence intervals.

Release gates include:

- domain and provider contract suites;
- multi-tenant authorization and cache-isolation tests;
- sandbox escape, egress, metadata, secret-canary, and resource-exhaustion tests;
- prompt-injection and tool-policy regression suites;
- connector authorization, stale/conflicting context, cross-tenant retrieval, and
  bundle-minimization suites;
- range containment, target/worker compromise, DNS/redirect drift, external-oracle,
  health-abort, kill-switch, and outcome-semantics suites;
- balanced internal workflow cases with temporal/repository holdouts;
- cost, latency, false-dismissal, calibration, and analyst-effort thresholds;
- canary deployment followed by shadow mode before changing workflow decisions.

Inspect remains the evaluation runner. Export normalized traces into the internal
telemetry system only after redaction. Sampling must never drop policy violations or
budget/audit events.

## Delivery sequence

### Phase 1: service extraction

Move Proposal 1 state and artifacts to PostgreSQL/object storage, add OIDC API,
idempotent jobs, worker leases, and a CLI client. Preserve local execution for tests.

### Phase 2: centralized security

Add workload identity, provider broker, tenant authorization, encrypted artifacts,
signed images, egress proxy, audit outbox, retention jobs, and adversarial isolation
tests.

Add the context broker, initial read-only source connectors, claim reconciliation,
bundle signing, just-in-time target refresh, and separate validation target ranges.

### Phase 3: review and integrations

Build the evidence workbench, reviewer assignment, approval workflows, SARIF import
and carefully gated export. Ticket/PR integrations go through a separate export
boundary.

### Phase 4: optimization

Add queue-aware routing, approved batch lanes, cache measurement, model experiments,
and shadow/canary promotion. Scale the worker pool only after profiling.

For a small experienced platform/AppSec team, this is roughly a 12-20 engineer-week
increment after a hardened Proposal 1 pilot. Enterprise identity, compliance,
high-assurance isolation, and integration requirements can dominate that range.

## Acceptance criteria

- Every API and artifact access is authorized to a tenant, repository, purpose, and
  revision.
- Jobs survive control-plane and worker restarts without duplicate external effects.
- No worker has a long-lived provider or cloud credential.
- Context connectors are tenant/source scoped, read-only, audited, and unavailable to
  models, provider workers, and target ranges.
- A compromised target sandbox cannot reach another tenant, the control plane,
  metadata endpoints, provider endpoints, or object storage except through scoped
  broker operations.
- Central budgets prevent queue-wide and tenant-specific cost exhaustion.
- Audit events reconstruct authorization, effective policy, tool calls, provider
  usage, reviewer decisions, and exports.
- Audit records also reconstruct context claims/conflicts/gaps, target-manifest and
  validation-plan digests, action dispatch, health events, oracles, and teardown.
- Production and eval data/sandboxes/credentials are separated.
- A provider/gateway outage degrades to a classified failure, not an unreviewed
  fallback.

## Advantages

- Central keys, budgets, policy, audit, retention, and model catalog.
- Durable workloads and shared sandbox capacity.
- Consistent review experience and labels for internal evals.
- Easier organization-wide cost and quality measurement.
- Supports gradual integration into CI and finding-management systems.

## Limitations

- A materially larger attack surface and operational burden.
- Multi-tenancy raises the consequence of an isolation failure.
- Queue, database, object store, identity, gateway, and sandbox upgrades need owners.
- Review UI and integrations can consume more effort than the model runtime.
- Central routing can hide provider semantics unless capability tests remain strict.

## Exit signals

Adopt Proposal 3 components only when the service needs large repeated benchmark
campaigns, local-model training, high-risk exploit environments, or isolation that a
shared container fleet cannot provide. Ordinary production scale is not itself a
reason to build an RL research platform.
