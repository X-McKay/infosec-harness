# Reference Architecture

## Design goals

The harness must support four workflows without giving an LLM ambient authority:

1. **Discovery:** inspect an authorized repository for plausible vulnerabilities.
2. **Change review:** look for security regressions in a bounded diff and its context.
3. **Threat modeling:** derive assets, trust boundaries, abuse cases, and mitigations
   from architecture evidence.
4. **Finding triage:** adjudicate imported SARIF or issue records while minimizing the
   dangerous error: dismissing a real vulnerability as a false positive.

The design optimizes for validated security value per dollar and analyst-hour, not
raw issue count or token volume.

## Non-goals

- Autonomous scanning of assets that are not named in an authorization manifest.
- Autonomous disclosure, ticket closure, pull-request creation, deployment, or
  interaction with production systems.
- Treating an LLM confidence score or a second LLM's agreement as proof.
- Training on held-out benchmark or production-evaluation answers.
- Normalizing every provider feature into a misleading lowest-common-denominator API.

## Core pipeline

```text
authorization + target snapshot + SecurityContextBundle
                         |
                         v
       ingest -> deterministic preflight -> scope/system map
                     |                           |
           scanner/SARIF import                 v
                     +----------------> plan candidates
                                                  |
                                       bounded investigation
                                                  |
                                   approved ValidationPlan
                                      /                 \
                           static evidence         isolated lab
                                      \                 /
                                       typed validation result
                                                  |
                                       adjudication + review
```

The controller implements explicit transitions. A model can request an allowed tool
or submit an artifact; it cannot choose a new workflow, enlarge scope, change policy,
or suppress an audit event.

Recommended states are:

```text
CREATED -> PREFLIGHTED -> PLANNED -> INVESTIGATING -> VALIDATING
        -> ADJUDICATING -> REVIEW_REQUIRED -> COMPLETE

Any state -> BUDGET_EXHAUSTED | POLICY_BLOCKED | INFRA_ERROR | CANCELLED
```

Infrastructure failures are never recorded as negative security results.

## Trust boundaries

### Control plane

Trusted Python code owns authorization, state transitions, provider credentials,
budgets, policy, artifact hashes, redaction, and audit records. It does not execute
target code. Provider API keys are available only to the provider adapter process or
gateway, never inside the target sandbox.

### Model plane

The remote or local model receives the minimum context for the current step. Its text,
tool arguments, confidence, and structured output are untrusted. The harness validates
schema and policy before using them.

### Target sandbox

The sandbox receives a disposable copy of an immutable repository snapshot and a
small set of typed tools. It contains no provider keys, developer SSH agent, cloud
metadata credentials, host home directory, Docker/Podman socket, or production token.
Its outputs are untrusted and bounded before returning to the controller.

### Context connector plane

Source-specific, read-only workers collect approved architecture, deployment, IAM,
API/data, telemetry, control, and ownership facts. The model never receives their
credentials or arbitrary query access. The control plane normalizes and redacts facts,
records provenance/freshness/coverage, preserves contradictions, and compiles a
minimal immutable view for the run.

### Validation range

Active validation runs in a separate disposable target range, not merely in the
analysis worker. A sealed worker is allowed to reach only synthetic target services;
the target range cannot reach production, enterprise networks, providers, controller,
or evidence verifier. Out-of-band policy, health monitoring, evidence collection, and
the kill switch stay outside both subjects.

### Human boundary

A named reviewer owns decisions with external or high-impact effects: expanding
scope, enabling egress, running an exploit mode, accepting a high/critical
false-positive disposition, publishing a report, or applying a patch outside the
ephemeral worktree.

## Authorization manifest

Every run starts with a validated manifest, generated or approved outside the model:

```yaml
schema_version: 1
engagement_id: eng-2026-001
target:
  repository: ssh://example.invalid/team/service.git
  revision: 0123456789abcdef
  paths: [src/, tests/]
  services: [service-canonical-id]
  environments: [staging]
purpose: vulnerability_review
allowed_actions: [read, search, static_scan, build, test]
network:
  mode: deny
exploit_mode: false
expires_at: 2026-08-10T00:00:00Z
requested_by: appsec@example.invalid
```

Production code should use a signed or server-issued form. The model sees a summary,
not a mutable copy.

## External context boundary

Before threat modeling or business-severity ranking, materialize a pinned
`SecurityContextBundle`. It is a bitemporal claim graph covering declared, deployed,
observed, effective, assessed, authorized, and inferred facts. Every fact records its
source snapshot, time, environment, sensitivity, authority, confidence, derivation,
and expiry; permission errors and missing instrumentation remain explicit coverage
gaps. Conflicting facts are inputs to investigation, not values to merge away.

The controller retrieves facts through reviewed connector operations and creates a
small task view. Repository text, tickets, catalog descriptions, logs, and model
inferences remain untrusted data. Immediately before dynamic validation, refresh the
high-risk facts and issue a signed, expiring `TestTargetManifest` for exact canonical
assets and artifact digests. See [External context and safe issue validation](context-and-safe-validation.md).

## Provider boundary

Use official provider SDKs behind a deliberately small asynchronous protocol. Keep
the application request and domain artifacts provider-neutral, while retaining a
capability record and an escape hatch for reviewed provider options.

```python
class ModelBackend(Protocol):
    async def generate(self, request: ModelRequest) -> ModelResult: ...

class ModelRequest(BaseModel):
    model: str
    system: str
    messages: list[Message]
    tools: list[ToolSpec]
    output_schema: dict[str, object] | None
    limits: GenerationLimits
    metadata: RunMetadata
    provider_options: dict[str, object] = {}

class ModelResult(BaseModel):
    message: Message
    tool_calls: list[ToolCall]
    parsed: dict[str, object] | None
    usage: Usage
    stop_reason: str
    provider_request_id: str | None
    model_version: str | None
```

The protocol must not erase meaningful differences such as prompt caching, reasoning
controls, batch APIs, tool-call formats, retention options, safety identifiers, or
server-side conversation state. Adapters advertise capabilities, reject unsupported
settings, and record the effective request. Pin exact model versions for evals; let a
reviewed production routing policy map stable tier names to provider model IDs.

Provider capability and routing records also include an `access_tier`, authorization
reference, expiry, permitted workflow/action classes, and required containment level.
Selecting a more capable or more permissive cyber model never expands the model's tool
or network authority; the control plane rejects a mismatch before dispatch.

Do not persist hidden reasoning. Persist the messages and tool interactions the API
actually exposes, structured artifacts, token/cost usage, and provider request IDs.

## Tool boundary

Expose narrow tools instead of a single ambient shell wherever practical:

- `search(pattern, paths, max_matches)`
- `read_file(path, start_line, end_line)`
- `list_tree(path, depth)`
- `run_static_scan(scanner, ruleset, paths)`
- `run_test(test_id, timeout_seconds)`
- `compile(target_id, timeout_seconds)`
- `submit_finding(finding)` / `submit_disposition(disposition)`

When a shell is genuinely required, accept a structured `argv`, a sandbox-relative
working directory token, an allowlisted environment, time/output limits, and a policy
decision ID. Avoid passing arbitrary host shell strings through the control plane.

Policy is enforced after schema validation and immediately before execution. Tool
results are length-limited, terminal escape sequences removed, tagged as untrusted
data, and stored by content hash. Repeated identical calls can be served from a
run-local cache.

## Finding contract

A finding is an evidence bundle, not prose:

```yaml
finding_id: stable-content-derived-id
snapshot: repository-and-revision
title: concise claim
cwe: CWE-XXX
locations:
  - path: src/example.py
    start_line: 10
claim:
  source: attacker-controlled input origin
  sink: security-sensitive operation
  path: relevant data/control-flow steps
  preconditions: [required deployment or configuration facts]
  impact: bounded consequence
evidence:
  - kind: code_reference
    artifact_hash: sha256:...
  - kind: test_result
    artifact_hash: sha256:...
validation:
  status: not_tested
  # Enum: reproduced, supported, not_reproduced, invalidated, not_applicable,
  # inconclusive, environment_mismatch, policy_blocked, authorization_failed,
  # infra_error, cleanup_failed, not_tested.
  attempts: []
coverage:
  status: unknown
  # Enum: complete, partial, unknown.
  examined_surfaces: []
  deferred_surfaces: []
  proof_gaps: []
severity:
  technical: high
  business: unknown
confidence: 0.0
disposition: candidate | confirmed | false_positive | inconclusive
provenance:
  run_id: run-...
  model: provider/model-version
  prompt_version: sha256:...
```

Separate severity, confidence, reproducibility, and disposition. They answer different
questions. Business severity requires deployment context and should remain `unknown`
when the harness lacks it.

`Not_reproduced` is never synonymous with `false_positive`. Only positive
counter-evidence with sufficient environment equivalence and oracle sensitivity can
produce `invalidated`; authoritative absence of the affected deployed component or
configuration can produce `not_applicable`.

For false-positive triage, require a falsifiable reason tied to the original rule:
sanitizer dominance, unreachable path, non-attacker-controlled source, non-sensitive
sink, type/range invariant, safe configuration, or duplicate. `No obvious exploit`
and model confidence are not valid reasons. A high/critical finding cannot be
auto-closed as false positive during the pilot.

An imported finding whose source revision, deployment, rule coverage, or relevant
surface cannot be matched is a `proof_gap` and remains `unknown`/`needs_review`; it is
not resolved merely because a later scan did not report it. Version-to-version
comparison should match root cause and evidence, preserve coverage changes, and
classify the result as new, persisting, reopened, resolved-with-proof, or unknown.

## Workflow specifics

### Vulnerability discovery

1. Pin and inventory the repository; identify languages, entry points, trust
   boundaries, security-sensitive APIs, and test commands.
2. Run deterministic analyzers and dependency/secret scanners first.
3. Partition by security surface, not arbitrary file chunks: authentication,
   authorization, parsing, serialization, command execution, storage, network, and
   cryptography.
4. Investigate a capped candidate list with targeted context.
5. Validate with an existing test, a safe generated regression test, static trace, or
   a minimally scoped proof in the isolated sandbox.
6. Report validated and inconclusive items separately; suppress unsupported guesses.

### Change review

Start with the diff, then retrieve callers, callees, tests, and policy/configuration
that can change exploitability. Compare both pre-change and post-change snapshots.
The output must cite changed lines and the surrounding invariant that was weakened.

### Threat modeling

Build an evidence-backed system model before generating threats:

1. Assets and security objectives.
2. Components and identities.
3. Data flows, trust boundaries, and entry points.
4. Existing controls and uncertain assumptions.
5. Abuse cases mapped to STRIDE/CWE/ATT&CK only where the mapping adds value.
6. Mitigations, owners, and validation questions.

Repository evidence is only one input. Resolve entry points, deployment, IAM, data
classification, service-to-service flows, third parties, controls, and business
invariants through the pinned external context bundle. Every premise cites a fact ID
or is labeled as an assumption, contradiction, gap, or question.

Score coverage against an expert checklist and known architecture facts. Semantic
similarity to a reference threat list is not sufficient: reward correct boundaries,
preconditions, prioritization, and absence of fabricated components.

### Existing-finding triage

Ingest SARIF without flattening rule metadata, code flows, fingerprints, suppressions,
or scanner provenance. Deduplicate deterministically. Retrieve the smallest complete
slice needed to test the scanner's claim. A low-cost model drafts the disposition; a
stronger model reviews only high-severity, uncertain, novel, or contradictory cases.
Human feedback becomes labeled evaluation data, not automatically trusted training
data.

## Sandbox baseline

For non-executing read/search/static-analysis tasks, use rootless Podman or Docker
with:

- immutable, digest-pinned base images and a read-only root filesystem;
- a disposable copy of the target plus bounded writable `tmpfs` scratch space;
- a non-root UID, all Linux capabilities dropped, `no-new-privileges`, seccomp, and
  AppArmor/SELinux where available;
- PID, memory, CPU, wall-clock, file-size, disk, and output quotas;
- no host namespace sharing, privileged mode, device mounts, home directory, SSH
  agent, cloud metadata route, or container engine socket;
- network disabled by default;
- automatic destruction and artifact hashing after each task.

Plain containers share the host kernel. If a workflow builds or executes
target-controlled code, require a configured stronger backend such as gVisor or Kata
Containers; if it is unavailable, the workflow stays read-only. High-risk proof or
exploit execution should use a separate guest kernel/microVM such as Firecracker, a
dedicated node/account, and a synthetic isolated target network. Never silently fall
back from the isolation level declared by task policy.

## Network enforcement and evidence

Network monitoring is not a compensating control for broad egress. Each episode starts
with a controller-signed, expiring `EgressPolicy` derived from the authorization or
`TestTargetManifest`. The model, repository, sandbox configuration, and target cannot
amend it. The policy has default deny for DNS, TCP, UDP, QUIC, raw sockets, host/bridge
interfaces, cloud metadata, IPv4 and IPv6. A read-only triage task should have no NIC
or route. A dynamic-lab task can name only its synthetic target edge and, when needed,
one task-scoped inference-broker edge.

The default topology keeps model-provider calls in the trusted controller and uses the
guest only as a typed tool executor, so an ordinary guest has no network interface at
all. A guest-side agent or provider path is an exception that must use the narrow broker
and receive a distinct `EgressPolicy`; it is never enabled merely because a repository
or model requests it.

The inference broker is not a general proxy. It holds the provider credential and
validates provider identity, TLS name, HTTP method/path, redirect behavior, content
type, request/response byte caps, connection count, rate, and the run's remaining
budget. It exposes neither generic `CONNECT` forwarding nor enterprise services. The
guest receives no provider, registry, CI, cloud, source-control, or artifact-store
credential. Context collection and dependency preparation run in separate workers with
separate identities; they are never routes available from an agent episode.

Enforcement and observation operate below and outside the guest, such as at the
microVM/veth/cgroup boundary plus the broker. Collect DNS requests, connection attempts,
resolved address, protocol/port, TLS and HTTP metadata, byte counts, process/cgroup,
policy rule and verdict. Record hashes and redacted metadata, not prompts, repository
content, tokens, or raw payloads. Append these records to a controller-owned,
tamper-evident event stream that the guest and target cannot read or alter.

```text
EgressPolicy
  run_id, manifest_digest, expires_at, policy_version
  allowed_edges[] { source_identity, destination_service, protocol, port,
                    dns_name_or_target_id, max_connections, max_bytes, max_rate }
  denied_classes[] { external_dns, registry, ci, artifact_store, cloud_metadata,
                     host_bridge, generic_proxy, raw_socket, unapproved_ipv4_ipv6 }
  containment { kill_worker, revoke_lease, quarantine_artifacts, alert_route }

NetworkEvidence
  event_id, run_id, guest_id, process_or_cgroup, timestamp
  decision_id, rule_id, protocol, direction, dns_name, resolved_ip, port
  tls_sni, http_method_path_hash, bytes_in, bytes_out, verdict, collector_health
```

An unapproved connection or DNS request, destination-resolution drift, proxy tunnel,
metadata/registry/CI/artifact access, policy quota breach, secret canary in a brokered
request, collector gap, or observer health failure is a containment event: stop the
worker, revoke task capabilities, quarantine evidence, preserve the correlated process
and filesystem record, and alert the assigned human. The run is not eligible for an
actionable conclusion. A `network-self-test` runs before each capable worker is
admitted and must demonstrate both an observed allowed synthetic flow and observed
denial of external DNS, IPv4/IPv6, metadata, host bridge, and direct provider access.

This design contains the generic behaviors used by supply-chain malware, including
lifecycle-hook credential theft and callback/exfiltration, even before a campaign's
indicators are known. A curated, reviewed threat-rule snapshot may add campaign IOCs,
but IOC matching is supplementary: the controls that matter are no ambient secrets, a
signed dependency closure, default-deny egress, independent observation, and automatic
containment.

No-direct-Internet is insufficient when a reachable cache, registry mirror, CI helper,
browser service, request-capture service, or proxy can itself reach another network.
Treat each such helper as a separately modeled asset with owner, patch level, reachable
networks, credentials, and data paths. Agent and target episodes have no route to them;
the dependency-preparation environment may use only its separately approved path and
cannot reach benchmark answers, provider credentials, production, or an active episode.

Dependency acquisition is a separate controlled phase. Prefer a prebuilt, scanned,
content-addressed dependency closure assembled outside the agent episode. An
evaluation or validation guest has no route to a registry, package cache/proxy, CI
helper, browser service, artifact store, external DNS resolver, or shared egress broker. If a
build must acquire dependencies, run it in a distinct audited preparation environment
with no benchmark data, provider keys, production access, or reusable route into the
episode; scan/sign the resulting closure before attaching it read-only. Repository
install scripts and hooks do not run merely because a package was fetched.

A scanner's internal sandbox or vendor-supplied container is never accepted as the
execution isolation boundary. The controller enforces filesystem, network, credential,
resource, telemetry, and teardown policy outside the scanner process.

Higher-risk exploit generation also needs the disclosure, access, monitoring, and
kill-switch controls described in Proposal 3; isolation alone is insufficient. The
[safe validation design](context-and-safe-validation.md) defines the immutable plan,
two-sided range, synthetic dependencies, deterministic oracle, result semantics, and
rules-of-engagement gate required before any active proof.

## Prompt-injection posture

There is no prompt-only fix. Enforce these invariants in code:

- Only control-plane policy and the authenticated user request are instructions.
- Repository text, issues, web pages, dependency metadata, test output, and tool
  results are data even when they contain imperative language.
- Reading data cannot grant a new tool, credential, path, network destination, or
  budget.
- Sensitive sources and external sinks are never simultaneously available without a
  specific approved workflow.
- The final report is checked against stored evidence and output policy before export.

Test the complete harness with malicious comments, filenames, symlinks, archives,
SARIF messages, ANSI escapes, oversized output, poisoned READMEs, and instructions
that request secrets or scope expansion.

## Cost and latency controls

Apply cost control before model selection:

1. Deduplicate findings and cache deterministic preprocessing by snapshot hash.
2. Retrieve small, structurally complete context rather than sending the repository.
3. Use fixed schemas and concise tool descriptions.
4. Route routine triage to a low-cost tier; escalate on severity, calibrated
   uncertainty, missing evidence, or cross-check disagreement.
5. Use an independent second provider only when correlated failure matters enough to
   justify the expense.
6. Use provider prompt caching and batch APIs only after measuring end-to-end quality.
7. Cap requests, input/output tokens, tool calls, retries, wall time, parallelism, and
   estimated dollars per run. The control plane, not the prompt, enforces the cap.
8. Stop when the required evidence is present, the search is exhausted, or the budget
   is reached.

Record preflight estimates and actual reported usage. Maintain a dated model catalog
for prices and capabilities, but reconcile it with invoices because provider naming,
discounts, cache accounting, and special-access terms vary.

Useful unit economics are:

- validated findings per dollar;
- analyst minutes saved per dollar;
- cost per correctly adjudicated imported finding;
- cost and latency per repository KLOC/language;
- marginal recall gained by escalation or an additional rollout.

Raw findings per dollar rewards noise and should not be used.

## Audit and data handling

Log state transitions, policy decisions, normalized tool calls/results, artifact
hashes, effective model/version, prompt version, usage, latency, and reviewer actions.
Redact secrets before both provider calls and logs. Encrypt sensitive artifacts at
rest and keep vulnerability data under an explicit retention policy.

Before using a remote provider, map the repository's data classification to current
contract terms: training use, retention, abuse monitoring, regional processing, zero
data retention eligibility, and subprocessors. Do not infer those terms from a model
name. Keep provider credentials short-lived and scoped through a broker or gateway.

## Suggested repository shape

```text
src/infosec_harness/
  domain/          # findings, evidence, tasks, budgets, authorization
  context/         # provenance graph, connectors, reconciliation, task views
  providers/       # protocol plus openai, anthropic, fake adapters
  policy/          # pure decisions and approval records
  runtime/         # state machine and bounded investigation loop
  tools/           # typed tools and SARIF/scanner adapters
  sandbox/         # backend protocol and OCI/gVisor/Kata/microVM implementations
  network/         # signed egress policy, broker contract, external flow evidence
  validation/      # plans, action catalog, target manifests, oracle adapters
  workflows/       # discovery, change review, threat model, triage
  artifacts/       # hashes, redaction, SQLite metadata
  telemetry/       # normalized redacted events
evals/             # Inspect tasks, scorers, manifests, held-out fixtures
gym/               # environment core, Gymnasium adapter, replay tooling
tests/              # unit, contract, integration, adversarial fixtures
prompts/            # versioned concise templates
policies/           # reviewed authorization and tool policies
```

The production runtime must not import from `evals/` or expose hidden scorer data to
the target sandbox.

## Implementation invariants

- A run without a valid, unexpired authorization manifest cannot start.
- Provider keys never enter a target sandbox.
- A discovered credential is quarantined as restricted evidence and cannot be replayed,
  used for authentication, or revealed to the model.
- A model cannot modify authorization, policy, budget, evidence, or audit history.
- Every finding references an immutable target revision and evidence artifact.
- Every deployment or business premise references a pinned context fact, assumption,
  conflict, or gap.
- Active validation requires a signed rules-of-engagement reference, immutable plan,
  fresh target manifest, synthetic fixtures, external oracle, and verified containment.
- `not_reproduced`, `invalidated`, environment mismatch, policy block, and
  infrastructure failure remain separate states.
- Every external side effect has a deterministic policy decision and, where required,
  a human approval.
- Budget exhaustion stops new model and tool work.
- Evaluation failures distinguish model failure, policy block, timeout, and
  infrastructure error.
- Hidden evaluation answers and reward code are inaccessible from the agent sandbox.
- Evaluation and validation guests cannot reach dependency registries/caches, artifact
  stores, CI helpers, answer stores, or general egress services.
- A missing network-policy decision, collector record, or collector health signal is a
  safety failure, not evidence that no connection occurred.
