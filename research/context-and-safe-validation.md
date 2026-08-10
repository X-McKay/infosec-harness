# External Context and Safe Issue Validation

## Recommendation

Treat threat-model context and penetration testing as two separate control-plane
capabilities:

1. Build a versioned `SecurityContextBundle` from repository and approved external
   sources. Every fact keeps its provenance, observation time, sensitivity, and
   confidence. The model receives a minimal task-specific view, not unrestricted
   access to enterprise systems or a large prompt assembled from raw records.
2. Validate a finding through the least dangerous experiment that can distinguish
   its hypothesis from a counter-hypothesis. Most work should stop at static proof,
   an existing test, or a component harness. Active testing belongs in a disposable,
   production-free lab under an explicit rules-of-engagement record.

Call the second capability an **issue validation lab**, not an autonomous penetration
tester. The objective is narrow: establish or refute the preconditions and impact of
an authorized finding. Discovery against live networks, unrestricted exploit
chaining, stealth, persistence, and production load testing are different engagement
classes and remain human-led.

The central evidence rule is:

> A failed reproduction is not evidence of absence unless the experiment represents
> every condition relevant to the claim and its oracle would have detected success.

`not_reproduced`, `environment_mismatch`, and `infra_error` must therefore
remain distinct from `invalidated`.

## Why a repository is not the system

Source code describes only part of a deployed security boundary. Exploitability and
business impact often depend on facts stored elsewhere:

- whether an endpoint is public, partner-facing, internal, or disabled;
- which load balancer, gateway, WAF, service mesh, or identity proxy precedes it;
- effective IAM bindings and service identities, not only declared policy files;
- deployment versions, environment variables, feature flags, and runtime defaults;
- database schemas, data classifications, tenancy rules, retention, and residency;
- calling services, webhook partners, queues, topics, and asynchronous consumers;
- business invariants such as approval limits, sequencing, idempotency, and
  separation of duties;
- compensating controls, accepted risks, incidents, and expiring exceptions;
- observed flows from telemetry, which may disagree with architecture documents.

OWASP's threat-modeling process begins with understanding what is being built and
models data flows, trust boundaries, processes, data stores, and external entities
before enumerating threats. Its business-logic guidance also emphasizes that generic
technical controls cannot replace domain-specific workflow invariants. See the
[OWASP Threat Modeling project](https://owasp.org/www-project-threat-modeling/),
[Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html),
and [Business Logic Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Business_Logic_Security_Cheat_Sheet.html).

The harness should therefore model a **time-bounded deployed system**, not infer a
permanent architecture from one repository revision.

## Security context bundle

### Canonical model

Use a small internal bitemporal claim graph rather than binding the domain model to
one catalog or threat-modeling product. The underlying `SecurityContextStore` keeps
valid time from each source and the time the harness learned a fact. A bundle is an
immutable, scope- and purpose-bound view of that store. It contains:

```yaml
schema_version: 1
bundle_id: scb-...
scope:
  product: payments
  services: [checkout-api]
  environments: [staging]
  accounts: [cloud-account-alias]
  regions: [region-alias]
  repository_revisions:
    checkout-api: 0123456789abcdef
as_of: 2026-08-09T14:00:00Z
expires_at: 2026-08-09T18:00:00Z
entities: []
relationships: []
facts: []
contradictions: []
gaps: []
assumptions: []
review:
  status: pending | approved | rejected
  reviewer: null
```

Useful entity types are:

- product, service, component, deployment, API, endpoint, queue, topic, and job;
- actor, human role, service identity, group, and administrative plane;
- cloud resource, network zone, trust boundary, data store, dataset, and secret
  reference;
- external provider, control, business process, owner, exception, and finding.

Useful relationships include `calls`, `exposes`, `reads`, `writes`, `publishes`,
`subscribes`, `authenticates_as`, `authorized_by`, `deployed_as`, `depends_on`,
`administered_by`, `stores`, and `crosses_boundary`.

Do not store secret values, customer records, raw session payloads, or general log
streams in this graph. Store references, structural metadata, aggregate observations,
hashes, and narrowly redacted excerpts.

Coverage gaps are first-class records with types such as `permission_denied`,
`unsupported_resource`, `not_instrumented`, `retention_elapsed`, `timeout`,
`ambiguous_identity`, and `no_record`. `No record` must never silently become `false`.
Use harness-owned stable entity IDs plus source-native aliases; never merge resources
by display name alone.

### Fact contract

Provenance applies to each fact, not to a source as a whole:

```yaml
fact_id: fact-...
subject: endpoint:checkout-submit
predicate: reachable_from
object: network_zone:internet
value: true
source:
  connector: cloud-inventory
  query_version: sha256:...
  snapshot: artifact:sha256:...
  source_record: resource-id-redacted
collected_at: 2026-08-09T13:45:00Z
valid_from: 2026-08-09T13:45:00Z
expires_at: 2026-08-09T14:45:00Z
evidence_class: observed
authority: authoritative_for_runtime_exposure
confidence: 0.98
sensitivity: internal
```

Required evidence classes are:

- `declared`: design documents, catalogs, IaC, API contracts, and policy intent;
- `deployed`: cloud, Kubernetes, gateway, DNS, image, and configuration inventory;
- `observed`: traces, access summaries, control telemetry, and recent behavior;
- `effective`: authorization simulation or another deterministic control decision;
- `asserted`: a ticket, questionnaire, exception, owner statement, or model proposal;
- `derived`: a deterministic join or documented inference from other fact IDs.

A model-created statement begins as `asserted` with low authority. It becomes a
trusted premise only after a connector, deterministic analysis, or named reviewer
corroborates it.

### Authority, freshness, and disagreement

There is no universal source priority. Resolve authority by predicate:

| Question | Preferred evidence | Important counter-evidence |
|---|---|---|
| What should exist? | reviewed design, service catalog, IaC | deployment drift |
| What is deployed? | cloud/Kubernetes/runtime inventory | stale inventory or dormant resources |
| What communicates? | recent traces plus network policy | sampling gaps and unexercised paths |
| Who can perform an action? | effective IAM/authz evaluation | application checks and token claims |
| What data is sensitive? | governed data catalog and owner | observed schemas and payload metadata |
| Is a control operating? | control-specific test/telemetry | exception records and bypass paths |
| What is business critical? | product owner/SRE-approved record | incident and availability history |

Keep contradictions instead of averaging them into confidence. A catalog declaring a
service internal while DNS and gateway inventory show a public route is itself a
review priority. Other valuable conflicts include IaC versus runtime policy, API
contracts versus observed anonymous calls, and a documented tenant boundary versus
cross-tenant data access in traces.

Each connector has a default TTL by fact type. Expired facts can orient an
investigation but cannot prove a current control. Pin the full bundle hash and every
underlying snapshot to the run so a later reviewer can distinguish environment drift
from model error.

## Context sources and connectors

### Initial source map

| Source | Facts to collect | Collection rule |
|---|---|---|
| Service catalog/on-call | ownership, product boundary, criticality, dependencies | read-only API; owner approval for criticality; ownership is not authorization |
| Cloud and Kubernetes inventory | resources, routes, identities, network boundaries, deployed image/config hashes | inventory APIs only; no mutation permission |
| Gateways, DNS, WAF, service mesh | ingress/egress and observed service edges | metadata and aggregate counters, not request bodies |
| IaC, Helm, deployment system | intended topology, configuration, revision, promotion history | pin revision and rendered manifest; do not ingest secret-bearing state by default |
| IdP and IAM | role/group/service-account graph and effective decisions | use a policy simulator or precomputed export; never give the model credentials |
| API/schema registries | endpoints, auth schemes, message schemas, webhooks | pin contract version and owner |
| Data catalog | classification, residency, retention, tenancy, stewardship | omit row data and direct identifiers |
| SBOM/VEX/provenance | components, dependency edges, exploitability assertions, artifact lineage | preserve issuer, signature, revision, and status reason |
| Artifact registry/cache/CI helper | dependency closure, proxy reachability, shared trust boundary, credentials, patch level, and egress capability | inventory as a first-class asset; never give an episode a live route |
| Telemetry/security systems | observed edges, control results, historical findings and incidents | aggregate, redact, bound time window, preserve sampling limits |
| Product/SRE records | business invariants, RTO/RPO, exceptions, compensating controls | named owner, expiry, and review state required |

[CycloneDX SBOM, SaaSBOM, and OBOM capabilities](https://cyclonedx.org/capabilities/)
can contribute component, service, endpoint, data-flow, and runtime metadata. The
[OpenSSF GUAC project](https://guac.sh/) is useful for software supply-chain
relationships. A [Backstage catalog](https://backstage.io/docs/features/software-catalog/system-model/)
can supply declared ownership and system topology. None should become the canonical
security truth by itself.

### Source-specific guidance

- For cloud topology, prefer provider inventory/index APIs and retain upstream update
  time and known ingestion lag. Examples are
  [AWS Config aggregators](https://docs.aws.amazon.com/config/latest/developerguide/aggregate-data.html),
  [Azure Resource Graph](https://learn.microsoft.com/en-us/azure/governance/resource-graph/overview),
  and [Google Cloud Asset Inventory](https://docs.cloud.google.com/asset-inventory/docs/asset-inventory-overview).
  Preserve desired IaC and observed cloud state separately. Do not ingest raw
  [Terraform state](https://developer.hashicorp.com/terraform/language/manage-sensitive-data)
  by default because it can contain sensitive values.
- For Kubernetes, retain namespace, UID, `resourceVersion`, desired `spec`, observed
  `status`, and owner references from the
  [Kubernetes object model](https://kubernetes.io/docs/concepts/overview/working-with-objects/).
  Do not grant `list` access to Secrets: it exposes their contents.
- For identity, collect principal, inherited scope, deny/boundary/condition, and
  time-bound eligibility, then prefer native effective-access analysis such as
  [AWS IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-concepts.html)
  or [Google Cloud Policy Analyzer](https://docs.cloud.google.com/policy-intelligence/docs/policy-analyzer-overview)
  over directory membership or prose.
- Parse HTTP and event declarations using versioned
  [OpenAPI](https://spec.openapis.org/oas/) and
  [AsyncAPI](https://www.asyncapi.com/docs/reference/specification/v3.1.0) documents.
  Keep declared routes and observed gateway/trace routes as separate fact sets.
- For data context, prefer schema, classification, ownership, residency, retention,
  and aggregate lineage. [OpenLineage](https://openlineage.io/docs/next/spec/object-model/)
  offers job/run/dataset relationships. Do not collect matched sensitive values or
  sampled production records into the harness.
- Normalize observed service identity and flows with
  [OpenTelemetry semantic conventions](https://opentelemetry.io/docs/specs/semconv/)
  and structured security metadata with [OCSF](https://ocsf.io/). A trace proves a
  path was observed; lack of a trace never proves a path is impossible.
- Bind source, build, artifact digest, and deployment using signed provenance such as
  [SLSA provenance](https://slsa.dev/spec/v1.2/provenance). Version tags alone are not
  stable joins. Treat VEX, exceptions, and control narratives as time-bounded issuer
  assertions, not self-proving facts.
- Use [OSCAL](https://pages.nist.gov/OSCAL/) adapters when the organization already
  maintains system-security plans, assessment results, or remediation plans. A
  declared control implementation remains distinct from current assessed evidence.

### Connector security

Connectors are trusted control-plane workers, not model tools. Each connector should:

- run under a source-specific read-only identity with resource and field allowlists;
- execute a reviewed, versioned query rather than model-authored SQL, log queries, or
  cloud API calls;
- enforce tenant, product, environment, and time-window scope before retrieval;
- redact secrets and direct identifiers, then validate the normalized schema;
- preserve a content hash and source locator in a protected evidence store;
- record query hash, connector/schema version, upstream ETag/resource version,
  pagination, source lag, caller-principal fingerprint, and partial/denied coverage;
- record collection errors, truncation, sampling, and authorization gaps;
- apply source-specific rate, record-count, byte, and retention limits;
- keep raw source material out of prompts unless a later approved evidence request
  selects a bounded excerpt.

The provider adapter receives no cloud, catalog, IdP, SIEM, or telemetry credential.
The model can request a typed question such as `get_effective_route(endpoint_id)`;
the controller decides whether an approved fact or a bounded connector query can
answer it.

### Collection and threat-model workflow

1. Resolve the authorization manifest to product, service, environment, account, and
   immutable repository/deployment identifiers. Ambiguous identity mapping stops the
   run.
2. Collect repository facts and approved external snapshots independently of the
   model.
3. Normalize, validate, redact, hash, and classify each fact. Preserve missing access
   and collection failures as gaps.
4. Join the graph using stable organizational identifiers. Detect conflicting facts,
   expiring controls, orphan services, unknown owners, and undeclared flows.
5. Generate a compact bundle view: assets, actors, entry points, trust boundaries,
   identities, sensitive operations, data flows, controls, contradictions, and open
   questions.
6. Obtain human review for the core scope, business invariants, high-impact assets,
   and exceptional access before using them to rank findings.
7. Let the investigator retrieve additional context only through typed, logged,
   task-bounded queries.
8. Produce a threat model whose every factual premise cites fact IDs. Mark unsupported
   items as hypotheses or questions.
9. Refresh on deployment events and source-specific TTLs. Never silently substitute a
   newer bundle during a running validation.

Immediately before active validation, re-check authorization, canonical target IDs,
deployed artifact digest, environment, exposure, IAM, data classification, downstream
side effects, health signals, contacts, and teardown. Compile the verified subset into
a signed, expiring `TestTargetManifest`. The executor accepts that manifest, never a
hostname, URL, or environment label authored by the model.

This extends the familiar threat-model questions with an evidence question: **How do
we know this fact, and for what time and environment was it true?**

## Safe validation ladder

Use the lowest level that can produce a sensitive and specific answer:

| Level | Method | Environment | Default authority |
|---|---|---|---|
| 0 | static trace, config proof, dependency/version proof, counterexample analysis | read-only snapshot | automatic within scope |
| 1 | existing tests, approved analyzers, replayed or mocked input | hardened build sandbox | automatic for cataloged commands |
| 2 | generated component regression harness with synthetic state | fresh gVisor/Kata guest or microVM | policy plus plan approval |
| 3 | disposable multi-service replica with mocked external systems | isolated target network and separate agent guest | AppSec approval |
| 4 | narrow staging canary validation | approved non-production environment, SRE monitoring | named owner, AppSec, SRE, time window |
| 5 | production or broad adversary emulation | outside this agent workflow | separate human-led engagement |

Promotion to a higher level requires a documented evidence gap that the lower level
cannot close. Severity alone does not authorize stronger tools.

NIST SP 800-115 recommends explicit planning, scope, limitations, test execution,
result analysis, and mitigation; its rules-of-engagement template covers boundaries,
risks, personnel, schedule, incident handling, data handling, and reporting. See
[NIST SP 800-115](https://csrc.nist.gov/pubs/sp/800/115/final). Map technical control
objectives to versioned [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
requirements and [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/)
tests where applicable.

The signed rules of engagement should bind the plan digest and identify exact assets,
owners, accounts/projects, regions, IPv4/IPv6 and FQDN rules, redirect/CNAME behavior,
third-party exclusions, permitted action-catalog entries, data class, request/byte/time
budgets, approvers, operator/on-call contacts, window, abort conditions, evidence
handling, notification, and incident procedure. Unknown assets inherit production
sensitivity and fail closed.

## Validation plan contract

A controller or analyst authors the binding fields. A model may propose the
hypothesis, preconditions, and oracle, but cannot approve or widen the plan.

```yaml
schema_version: 1
plan_id: vp-...
finding_id: finding-...
authorization_ref: engagement-and-signature
target:
  repository_revision: 0123456789abcdef
  deployment_artifacts: [sha256:...]
  security_context_bundle: scb-...
hypothesis: unauthorized tenant B can read tenant A object through endpoint E
counter_hypothesis: ownership enforcement rejects every cross-tenant object reference
equivalence_claims:
  - authorization middleware and policy match the affected deployment
  - routing and data-access topology match the finding preconditions
validation_level: 2
environment:
  image_digests: [sha256:...]
  synthetic_fixture: fixture-id
  network_policy: isolated-target-v1
  egress_policy_digest: sha256:...
identities: [synthetic-tenant-a, synthetic-tenant-b]
allowed_actions: [named-test-driver, read-evidence]
forbidden_actions: [public-egress, persistence, destructive-load]
budgets:
  wall_seconds: 300
  total_requests: 50
  requests_per_second: 2
  max_payload_bytes: 65536
  cpu: bounded-profile
oracle:
  success: tenant-b receives marked tenant-a record
  counter_evidence: all authorized variants succeed and all cross-tenant variants fail
  health_checks: [target-ready, audit-stream-ready]
abort_conditions: [health-check-failure, rate-limit, unexpected-egress, policy-event, unexpected-secret]
evidence: [request-summary, response-hash, policy-decision, database-diff, network-log, network-observer-health]
approvals: []
expires_at: 2026-08-10T00:00:00Z
```

Also record cleanup as **destroy and independently verify**, not a command the model
is trusted to run. Plans and approvals are immutable once execution begins; a changed
scope creates a new plan.

### Execution gates

Execute a plan through deterministic gates:

1. `AUTHORIZED`: verify rules-of-engagement signature, ownership, exclusions, plan
   digest, approvers, and validity window.
2. `CONTEXT_READY`: verify target identity, deployed digest, environment, data class,
   downstream effects, and all claim preconditions required by the experiment.
3. `TWIN_READY`: deploy the exact approved artifact with synthetic fixtures, service
   fakes, target health baseline, and a patched/clean control where practical.
4. `CONTAINMENT_READY`: prove denial of host/control-plane access, metadata, public
   and enterprise networks, ambient credentials, engine sockets, and out-of-scope
   filesystem paths, package registries/caches/proxies, CI helpers, artifact stores,
   benchmark-answer services, and neighboring workloads.
5. `SAFETY_READY`: exercise the independent network circuit breaker, process kill,
   lease revocation, health abort, and destructive teardown before model-driven work.
6. `APPROVED`: evaluate the action risk class and obtain any live approval. An expired
   approval fails closed.
7. `EXECUTING`: issue a short-lived capability for each registered action, revalidate
   target and cumulative budgets immediately before dispatch, and stop on the first
   sufficient oracle or any health/policy event.
8. `EVIDENCED`: seal authorization, context, target, image, policy, prompt/model, tool,
   proposed/allowed/denied action, network, resource, and oracle records.
9. `CLEAN`: revoke every lease, destroy the range, and independently compare external
   state with the baseline. A discrepancy blocks adjudication.
10. `ADJUDICATED`: apply the result semantics below and send consequential decisions
    to a human reviewer.

Changing a model, prompt, context builder, tool schema, action catalog, policy,
sandbox image, oracle, or network layer changes the configuration under test and
requires the relevant safety and quality gates again.

## Validation lab architecture

Containment is two-sided. The worker boundary protects the controller and host from
target-controlled code. The sealed target range independently protects production,
the enterprise network, and third parties from the worker and model. A microVM that
can reach production is not a safe validation environment merely because the worker
itself is isolated.

```text
trusted control plane
  authorization -> plan compiler -> deterministic policy -> scheduler
         |                                      |
         |                              out-of-band kill switch
         v                                      |
separate agent guest ---- isolated broker ---- target replica subnet
  no enterprise creds       typed actions       app + synthetic dependencies
  no host/control access     hard quotas         mock IdP/DB/queue/email/payment
         |                                      |
         +------------- bounded results --------+
                                |
                  immutable out-of-band evidence collector
                                |
                  independent verifier and human review
```

The agent guest and target replica are different isolation subjects. Compromise of the
target must not expose the provider token, controller, grader, evidence store, host,
or enterprise network. For target-controlled execution, use a separate-kernel
boundary such as a Firecracker-class microVM or an approved Kata deployment. gVisor
can be a middle tier after compatibility and escape tests. Plain rootless containers
remain appropriate only for non-executing inspection because they share the host
kernel.

The environment should have:

- no public IP, corporate network route, cloud metadata route, host socket, shared
  home directory, SSH agent, or ambient credential;
- internal DNS with only named synthetic targets and a default-deny egress proxy;
- an action broker that rechecks FQDN, CNAME/redirect behavior, resolved IPv4/IPv6,
  canonical target ID, and plan scope immediately before each connection;
- a controller-signed, expiring egress policy that names every permitted edge and
  quota. The worker has no route for general DNS, public/enterprise traffic, package
  registries, CI/artifact systems, metadata, host bridges, or generic proxy tunnels;
- a host/hypervisor-side flow collector that associates each DNS and connection attempt
  with the guest/process, policy decision, destination resolution, TLS/HTTP metadata,
  byte counts, and verdict. A missing collector health signal or unmatched flow fails
  the attempt closed;
- separate fake IdP, database/object store, queue, email/payment/webhook sinks, and a
  canary callback service;
- non-root identities, read-only base images, capability drop, syscall/MAC policy,
  PID/CPU/memory/disk/file/output/wall-time quotas, and deterministic timeouts;
- immutable network, process, filesystem, application-audit, and data-state evidence
  collected outside the agent's writable environment;
- target health checks and a kill switch that do not depend on the model or target;
- image destruction after each attempt and re-creation between findings.

The oracle and evidence sink are unreadable and unmodifiable by the worker and target.

The network observer is part of containment, not a reporting feature. An unapproved
DNS lookup or connection, DNS rebinding or address-family drift, generic proxy use,
unexpected registry/CI/metadata/artifact access, quota breach, or observer failure
must immediately kill the worker, revoke its short-lived capabilities, quarantine its
artifacts, and create a safety event for the named owner. Before model work, the lab
must prove that the observer records both an allowed synthetic request and denials for
external DNS, IPv4/IPv6, host/metadata paths, and direct provider connectivity.

NVIDIA's current sandboxing guidance similarly recommends blocking arbitrary egress,
external reads and writes, configuration changes, metadata, and ambient credentials,
with fresh approval for exceptions and stronger kernel isolation for hostile
execution. See [Practical Security Guidance for Sandboxing Agentic Workflows](https://developer.nvidia.com/blog/practical-security-guidance-for-sandboxing-agentic-workflows-and-managing-execution-risk/).

### Production-shaped, production-free fixtures

Reproduce only the structure needed for the hypothesis:

- build from signed, digest-pinned application and infrastructure artifacts;
- generate relationally valid fixtures from schemas and policy rather than copying or
  merely masking customer data;
- replace real identities and secrets with short-lived canary identities and values;
- replace cloud services, metadata, webhooks, notifications, payments, and queues with
  local fakes or sinks;
- replace public DNS and addresses with lab-only names;
- attach a complete signed, read-only dependency closure before the episode starts;
  do not route the agent or target to an artifact mirror, registry, cache, proxy, or
  build/CI helper during execution;
- preserve the relevant policy, routing, tenancy, serialization, and configuration
  semantics, then list every known mismatch.

Environment fidelity is a set of testable claims, not a label such as "staging-like."
The validation result must cite which equivalence claims passed, failed, or were never
checked.

NIST notes that de-identification needs explicit governance and measurement; masking
alone is not a guarantee against re-identification. Prefer wholly generated fixtures
and treat any use of derived data under [NIST SP 800-188](https://csrc.nist.gov/pubs/sp/800/188/final)
as a separate privacy-reviewed workflow.

## Safe validation patterns

These patterns describe evidence objectives, not exploit playbooks:

| Finding class | Safe lab technique | Deterministic oracle |
|---|---|---|
| authorization/tenant isolation | synthetic users, roles, tenants, and marked objects | permitted matrix succeeds; forbidden matrix never returns marked data |
| injection/control-flow | inert instrumented sink and benign marker | marker reaches forbidden operation without invoking a host shell or external system |
| SSRF | fake metadata and callback services inside the isolated subnet | request reaches only the named canary; every other destination is blocked |
| secret exposure | generated canary values in synthetic stores | canary appears in a disallowed response, log, or artifact |
| traversal/file access | minimal synthetic filesystem with marked files | marker outside the intended logical root becomes readable or writable |
| unsafe deserialization/code execution | isolated marker action with no persistence or egress | expected marker state changes under the vulnerable path |
| race/business logic | synthetic accounts and bounded concurrent operations | balance, uniqueness, sequence, or approval invariant is violated |
| browser/XSS | local browser, local origins, and canary sink | forbidden script effect occurs without an Internet callback |
| cloud IAM | offline effective-policy evaluator and synthetic resource graph | forbidden principal-action-resource tuple evaluates allowed |
| supply chain | private lab registry with harmless synthetic packages | resolver or build selects the prohibited marked artifact |

Do not give an agent a general vulnerability scanner or shell merely because a named
driver exists. [ZAP's Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/)
can express pinned targets, authentication, jobs, and job tests; expose only reviewed
plans against lab targets. Pin any templates, add-ons, wordlists, and dependencies and
disable self-update during an episode.

For detection-engineering exercises, MITRE's
[Adversary Emulation Plans](https://attack.mitre.org/resources/adversary-emulation-plans/)
and [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team/wiki/Getting-started)
offer useful structured tests. Keep that work in a separate isolated range with
manually reviewed, pinned tests and explicit permission. A test's cleanup script is
not an isolation mechanism; destroy and recreate the host.

### Prohibited defaults

Without a separate human-led engagement, the agent cannot perform:

- testing against production, employee endpoints, third parties, or public targets;
- persistence, stealth, evasion, phishing, credential harvesting, or lateral movement;
- access to real customer data, enterprise secrets, or live privileged identities;
- testing, replaying, or authenticating with a credential discovered in target content,
  logs, public material, registries, or tool output; quarantine it for human response;
- denial-of-service, unbounded concurrency, destructive payloads, or data corruption;
- real email, SMS, payment, webhook, queue, or incident-response side effects;
- unrestricted Internet access, arbitrary DNS, package installation, or scanner
  self-update;
- exploit chaining beyond the exact finding hypothesis or creation of reusable
  weaponized artifacts.

Availability findings should normally use unit/property tests, resource-bounded
microbenchmarks, static complexity evidence, or an SRE-owned performance environment.
An autonomous agent must not load-test a shared staging system.

## Result semantics and false-positive decisions

Use these terminal validation states:

- `reproduced`: the success oracle fired under represented preconditions;
- `supported`: non-dynamic evidence establishes the vulnerable path and preconditions;
- `not_reproduced`: the oracle did not fire, but equivalence or sensitivity is
  incomplete;
- `invalidated`: a relevant countercondition was proven and the environment and
  oracle were sufficient to test the claim;
- `not_applicable`: authoritative deployment evidence proves that the affected
  component, route, artifact, or configuration is absent from the scoped system;
- `inconclusive`: evidence supports neither conclusion within the budget;
- `environment_mismatch`: a relevant production/deployment precondition could not be
  represented;
- `policy_blocked`: the required action was outside authorization;
- `infra_error`: the environment or evidence collector failed;
- `authorization_failed`: scope, ownership, signature, or approval was invalid;
- `cleanup_failed`: teardown or external-state verification was incomplete.

`unexpected_secret_discovered` is a terminal policy event, not a validation result:
redact and fingerprint the material, remove it from model-visible artifacts, preserve
only the restricted evidence record, stop the episode, and send it to the credential
response process. It cannot authorize an action or enlarge the test scope.

Only `reproduced` or `supported` can confirm a finding. Only `invalidated` or
`not_applicable`, paired with explicit counter-evidence and the original
scanner/claim semantics, can support a false-positive recommendation. High-impact
dismissal still requires a human review.

Examples of valid counter-evidence include a deterministic proof that a source is not
attacker-controlled, a dominating and correctly configured control, an unreachable
path in the affected artifact, an effective authorization decision covering every
relevant variant, or a type/range/business invariant enforced at the actual boundary.
An empty scanner result, model disagreement, timeout, blocked action, or one failed
test is not counter-evidence.

For strong dynamic confirmation, use a differential oracle where practical: it fires
on the vulnerable artifact but not on a patched or known-clean artifact with otherwise
identical fixtures. Stop the exercise on the first sufficient proof.

The independent verifier receives the claim, pinned context bundle, plan, facts,
oracles, and artifacts. It does not receive the investigator's persuasive narrative
as an instruction. Where possible, the verifier is deterministic; a second model can
review evidence quality but cannot override a failed oracle or policy result.

## Data handling and cost control

- Classify each fact and artifact before provider routing. Some bundles must remain
  local or use only approved endpoints/features.
- Generate task views from IDs and structural facts. Retrieve code, config, and
  telemetry excerpts only when they answer a declared question.
- Aggregate traces and logs into edges, counts, authorization outcomes, and bounded
  samples; do not upload general log streams or customer payloads.
- Redact secrets and direct identifiers before both model calls and telemetry. Use
  canary values in the lab so leakage remains detectable without consequence.
- Partition caches by tenant, source, bundle hash, and classification. Never reuse a
  context cache across tenants.
- Cache signed connector snapshots and deterministic joins. Spend strong-model tokens
  on contradictions, missing preconditions, and validation design rather than raw
  inventory summarization.
- Apply separate budgets to context collection, model retrieval, lab provisioning,
  validation actions, and independent verification.

## Evaluation requirements

Add context and validation cases to the private suite:

- a repository-only threat model versus the same task with a correct external bundle;
- stale, missing, sampled, and contradictory facts;
- poisoned catalog descriptions, tickets, logs, SARIF, and architecture documents;
- cross-service and asynchronous flows that no single repository contains;
- business-logic cases requiring an owner-provided invariant;
- vulnerable and safe variants under multiple deployment configurations;
- reproduction failures caused by environment mismatch, insensitive oracle, policy
  block, target crash, and infrastructure failure;
- synthetic lab escape, egress, metadata, credential, resource-exhaustion, and
  evidence-tampering attempts;
- tests showing that a model cannot turn `not_reproduced` into `false_positive`.

Metrics should include context-fact precision/recall, provenance accuracy, boundary
and flow coverage, contradiction detection, unanswered critical questions, validation
oracle sensitivity/specificity, environment-fidelity coverage, correct result-state
classification, policy violations, analyst minutes, and dollars per correctly
adjudicated finding.

## Phased implementation

### Phase A: context pilot

Define the bundle/fact schemas and manually assemble 20-50 representative systems.
Start with repository metadata, service catalog, deployment inventory, API contracts,
and owner-reviewed business invariants. Measure whether these facts change threat
priorities and finding dispositions before adding more connectors.

### Phase B: read-only connectors

Add source-specific workers for cloud/Kubernetes inventory, IAM simulation, data
catalog metadata, SBOM/VEX, and aggregate telemetry. Implement TTLs, contradiction
detection, field-level classification, redaction, bundle hashes, and access audits.

### Phase C: component validation

Implement the `ValidationPlan`, named test-driver catalog, separate-kernel backend,
synthetic identity/data fixtures, external-service mocks, out-of-band evidence
collector, and destructive teardown. Begin with authorization, injection, traversal,
SSRF, and business-invariant cases that have deterministic oracles.

Use the emerging [OWASP Autonomous Penetration Testing Standard](https://owasp.org/APTS/)
as an additional checklist for machine-readable scope, pre-action validation, safety,
auditability, and reporting. It is new and not a certification regime; review its
specific thresholds against local risk rather than adopting them uncritically.

### Phase D: replica and staging gates

Add disposable multi-service replicas only where component tests cannot represent the
claim. Add narrowly approved staging canaries after AppSec/SRE review, automated
health aborts, and several months of lab evidence. Production active testing stays a
separate program.

## Acceptance criteria

- Every threat-model premise and business-severity decision cites a fact, assertion,
  assumption, or explicitly recorded gap.
- Every external fact has source, query/snapshot, collection time, environment,
  authority, sensitivity, and expiry metadata.
- Connector credentials are read-only, source-scoped, unavailable to models and
  target sandboxes, and independently audited.
- Contradictions and expired facts remain visible; the system never silently chooses
  the most convenient source.
- Every dynamic action is covered by a valid authorization and immutable validation
  plan with named target, allowed action, budget, oracle, abort condition, and owner.
- The agent and target have no route to production, metadata, the public Internet,
  the controller, provider credentials, hidden graders, or enterprise secrets.
- A target compromise cannot alter the out-of-band evidence, verifier, policy, health
  monitor, or kill switch.
- `not_reproduced`, environment/policy/infrastructure failures, and `invalidated` are
  represented and evaluated separately.
- Teardown destroys the environment and verifies that no external side effect or
  retained canary remains.
