# Security Agent Harness Proposal

## Executive Summary

Build a Python-based internal security-review harness that helps Senior Engineers and
InfoSec specialists investigate vulnerability findings, review code and changes, and
produce evidence-backed remediation recommendations. It will use approved OpenAI and
Anthropic models behind one provider-neutral interface, but the models will not receive
unrestricted access to repositories, internal systems, credentials, or production.

The recommended first release is a bounded pilot for imported scanner findings and
read-only repository review. It combines deterministic security tools with a model that
gathers and explains evidence. Consequential conclusions remain subject to human
review. Active penetration testing, automatic patch merge, and production access are
later capabilities, contingent on separate safety and operating gates.

The pilot answers a practical question: does this approach increase validated,
actionable findings per analyst-hour while maintaining approved safety, quality, and
cost limits? It is not a commitment to autonomous security operations or model
training.

A second design objective is to avoid creating a new security platform with a broad
dependency and plugin surface. The harness should add authority and integrations only
when they deliver measured value that cannot be obtained with its existing, owned
components.

## Problem and Opportunity

Security teams spend substantial time determining whether scanner findings are real,
understanding how a finding applies to a specific deployment, collecting evidence for
engineers, and following remediation through to a verified fix. Existing scanners are
valuable, but their output is often incomplete, duplicated, or difficult to prioritize.

Modern models can read source code, security findings, and structured system context
well enough to reduce the investigation burden. Their output is not sufficiently
reliable to be the final authority, and agent tooling introduces risks such as prompt
injection, data leakage, unexpected tool use, and uncontrolled spend. The harness
makes models useful investigators while keeping policy, scope, execution, evidence,
and release decisions in conventional software controls.

## What We Would Build

The product is a command-line and CI-integrated workflow service for authorized
security work. The initial deployment is single-tenant and operated by a small AppSec
team, not a public-facing application.

### Core Capabilities

1. **Finding triage and false-positive review**
   - Import SARIF and scanner findings while preserving rule, location, code flow,
     repository revision, and scanner metadata.
   - Collect evidence for and against a finding: source/sink path, controls,
     reachability, configuration, deployment assumptions, and proof gaps.
   - Return a structured disposition: confirmed, likely, unlikely, false positive,
     insufficient evidence, or needs review. Suppression or closure requires human
     approval and positive counter-evidence.

2. **Read-only repository and diff review**
   - Review authorized source snapshots and pull-request diffs using constrained
     search/read tools plus deterministic analyzers.
   - Identify candidate security issues, rank them using the system threat model, and
     create evidence packs that an engineer can inspect and reproduce.

3. **Threat-model assistance with system context**
   - Assemble a versioned context bundle from approved service catalog,
     deployment/artifact metadata, API contracts, SBOM/VEX, ownership, and business
     invariants.
   - Show provenance, freshness, conflicts, and information gaps rather than treating
     documentation or model inference as ground truth.

4. **Evidence, reports, and remediation tracking**
   - Produce human-readable reports plus JSON/SARIF output with source locations,
     counter-evidence, assumptions, cost, coverage, and next steps.
   - Record linkage from a validated finding to owner review, patch, test, deployment
     artifact, and verified remediation.

5. **Measurement and continuous improvement**
   - Record quality, analyst time, cost, latency, coverage, policy decisions, and
     safety events for every run.
   - Evaluate changes against a private, held-out corpus before promotion. Public
     benchmarks provide comparison and regression signals, not the release gate.

### Explicitly Not in the First Release

- Autonomous external scanning, public-target testing, or production penetration tests.
- Direct access to secrets, developer machines, cloud credentials, or unrestricted
  internal APIs.
- Automatic finding closure, ticket creation, code merge, deployment, or remediation.
- A free-form multi-agent swarm, unrestricted shell, browser, MCP marketplace, or
  online reinforcement learning loop.

## How Teams Would Use It

### Senior Engineers

An engineer receives a finding report or requests a review of an authorized revision.
The harness returns an evidence pack: affected files and lines, alleged attack path,
required preconditions, relevant controls, contrary evidence, confidence, and the
reason human review is required. The engineer can inspect cited artifacts, correct
assumptions, request additional evidence within approved scope, or implement a fix.
The harness then helps record regression-test and deployed-remediation evidence.

The expected benefit is less time reconstructing scanner output and more time deciding
and implementing the right fix. It does not replace code review or security ownership.

### InfoSec and AppSec Specialists

AppSec defines approved workflow, review thresholds, data classification, allowed
tools, budgets, and target scope. Specialists review high-impact dispositions, approve
exceptions and active-validation plans, maintain the labeled evaluation corpus, and
use reports to identify false-positive patterns, coverage gaps, tool weaknesses, and
remediation aging.

Every model request, tool decision, evidence reference, budget decision, policy block,
and final disposition is traceable to a versioned run configuration.

### Typical Pilot Workflow

1. An analyst imports findings or selects an authorized repository revision.
2. The controller verifies scope, data rules, budgets, and the available context.
3. Deterministic tools inventory and deduplicate candidates before model use.
4. The model investigates through typed, read-only tools and returns a validated schema
   rather than an unstructured conclusion.
5. An independent verifier and policy checks assess evidence and proof gaps.
6. A human reviews significant outcomes; the report is exported to the existing
   security and engineering workflow.
7. Metrics and reviewer feedback feed offline evaluation, never automatic production
   self-modification.

## Security and Operating Model

The model is an investigator, not a security boundary or final authority.

- **Least privilege:** repository content, scanner output, issues, tool results, and
  external context are untrusted data. The model cannot turn them into instructions or
  grant itself more access.
- **Hard execution boundary:** read-only work uses a network-disabled, rootless
  container. Future target-code execution uses a separate disposable
  gVisor/Kata/microVM-class environment with no host mounts, credentials, or general
  egress.
- **Network control and evidence:** every worker receives an expiring, signed egress
  policy derived from the approved task, not from model output. Enforcement and flow
  collection run outside the guest. Any unapproved connection, DNS request, redirect,
  resolution change, byte/rate limit breach, or observer failure kills the worker,
  revokes its lease, and quarantines its artifacts.
- **Approval and scope controls:** a signed manifest defines targets, environments,
  allowed actions, time window, cost limits, and exclusions. The tool broker, not the
  model, enforces it.
- **Data protection:** prompts and telemetry use minimum necessary, redacted data;
  local encrypted artifact storage is the pilot default. Provider retention and data
  classification rules are checked before an excerpt is sent externally.
- **Cost control:** each workflow has provider, token, tool, concurrency, wall-time,
  and dollar budgets. Stronger models are reserved for ambiguous or high-impact cases.
- **Human accountability:** humans approve consequential suppression, closure, external
  writes, active validation, and any policy or access-level change.

## Minimum Trusted Base and Integration Policy

The harness will keep its trusted base deliberately small: the owned Python controller,
typed policy and evidence models, direct official provider adapters, local artifact
storage, and a selected sandbox backend. It will not become an integration hub or an
agent-plugin platform.

- **No runtime installation:** agents and jobs cannot download packages, skills, MCP
  servers, rules, models, browser extensions, or containers. Every executable input is
  part of a signed, pinned dependency closure prepared outside the run.
- **No dynamic extensions:** workflows and tools are owned, typed, versioned code.
  Third-party skills, MCP servers, general agent frameworks, shared memory services,
  vector databases, graph databases, and provider gateways are excluded from the
  pilot.
- **Evidence slices before new retrieval platforms:** the initial context capability
  combines SARIF code flows, deterministic source search, approved configuration, and
  existing analyzer output into a bounded `EvidenceSlice`. A graph/RAG product is not a
  prerequisite and must prove material improvement on the private development corpus
  before consideration.
- **Integration admission:** a new dependency or service needs a named owner, a
  documented threat model, license and data review, pinned build/digest and SBOM,
  offline/replay tests, a containment profile, rollback plan, and a preregistered value
  metric. It is accepted only when the measured benefit outweighs its attack surface,
  operating cost, and maintenance burden.
- **Default denial:** an integration that adds credentials, egress, code execution,
  persistent cross-repository data, or model/provider access starts prohibited until a
  signed exception is approved.

## Proposed Technology Approach

| Area | Pilot choice | Why it is suitable |
|---|---|---|
| Implementation | Python 3.12 | Mature provider SDKs, validation, security, and evaluation ecosystem. |
| Development toolchain | `mise`, `uv`, `just`, `prek` | Reproducible runtimes, dependency locks, common commands, and fast policy checks. |
| Model integration | Thin native OpenAI and Anthropic adapters behind `ModelBackend` | Avoids lock-in while preserving provider-specific safety, cost, and structured-output capabilities. |
| Workflow engine | Explicit Python state machine | Easier to review, test, replay, and attribute cost than a general autonomous graph. |
| Data model | Pydantic and JSON Schema | Enforces typed findings, evidence, policies, context, and model outputs. |
| Security evidence | SARIF import, selected static tools, SBOM/VEX inputs | Preserves deterministic evidence and scanner provenance. |
| Context | Provenance-aware `SecurityContextBundle` | Separates observed facts, declarations, effective permissions, and hypotheses. |
| Storage and audit | SQLite, content-addressed local artifacts, JSONL audit | Low operational overhead with reproducible, inspectable pilot runs. |
| Telemetry | Redacted local events mapped to OpenTelemetry-compatible fields | Enables quality, safety, and cost reporting without default third-party export. |
| Network safety | Controller-mediated inference, signed per-run egress policy, host-side flow collector, narrow exception-only broker | Keeps ordinary workers offline and detects/stops any authorized exception without placing provider or enterprise credentials in the guest. |
| Evaluation | Inspect AI adapter, internal corpus, selected public suites | Provider-neutral, repeatable evaluation while keeping the control plane local. |
| Sandboxing | Rootless OCI for no-exec work; stronger isolation for active validation | Matches isolation strength to risk and prevents silent fallback. |

[`abox`](https://github.com/X-McKay/abox) is the explicit exception to the default
third-party-integration posture because it is owned and maintained by the harness team.
It is an optional execution backend for agentic repository work and evaluation, using
Cloud Hypervisor microVMs, per-task worktrees, mediated egress, host-held credential
injection, and audit logs. It remains behind the harness's `SandboxBackend` interface,
not the authorization or policy layer.

For the pilot, `abox` may support an isolated agent worker with a task-scoped inference
route and dedicated service credentials. The harness must retain control of target
scope, budgets, evidence, and human approval. Repository-controlled `.abox`
configuration and prepare scripts are untrusted input; use harness-owned, reviewed
profiles. Disable host-command grants, SSH/cloud credentials, host-port bridges, and
general egress by default. For any future active validation, the agent worker and
synthetic vulnerable target remain separate isolated environments, and `abox` must pass
negative-reachability, independent network-observer, audit, and teardown tests before
use. Its proxy is an enforcement point only when the harness supplies the reviewed,
signed profile; it never substitutes for the harness policy engine or host-side flow
collector.

The first release intentionally excludes a centralized model gateway, queue, web UI,
vector database, graph database, document-processing service, shared agent memory,
agent-plugin marketplace, and general agent framework. These are not prerequisites for
proving value and would expand the trusted base.

## Evaluation, Value, and Rollout

The pilot starts with 20-50 carefully reviewed representative cases and a matched human
baseline. A private, time- and repository-separated holdout is the release gate,
supported by public regression suites such as OWASP Benchmark and selected Inspect
security tasks.

We will measure:

- Accepted true positives, precision, false-dismissal rate, calibration, and evidence
  validity by severity, CWE, language, and repository type.
- Analyst investigation time, review burden, time to disposition, and time to verified
  remediation.
- Cost per run, correct disposition, and verified true positive, including model,
  tool, sandbox, and storage costs.
- Policy denials, unexpected egress, secret/canary exposure, grader-integrity events,
  sandbox containment, observer coverage, deny-to-containment latency, and teardown
  success.

Promotion requires improvement over the current process on the held-out corpus without
violating AppSec-approved safety, false-dismissal, cost, or latency limits. Shadow mode
precedes any workflow change; production runs never alter prompts, policies, access,
or model behavior automatically.

### Phased Delivery

| Phase | Outcome | Indicative scope |
|---|---|---|
| 0. Baseline and governance | Named owners, authorized scope, data rules, baseline labels, acceptance metrics | Establish controls before model selection. |
| 1. Read-only pilot | Provider adapters, SARIF triage, evidence reports, no-exec sandbox, network self-test, audit trail | Demonstrate value on one AppSec workflow. |
| 2. Evaluation and context | Benchmark registry, private release gate, bounded evidence slices, context bundle, telemetry/cost reporting, shadow mode | Demonstrate quality, safety, and economics without a graph/RAG or memory service. |
| 3. Safe validation lab | Synthetic range, explicit validation plans, deterministic oracles, microVM-class isolation | Only after pilot and containment gates pass. |
| 4. Controlled service | Shared workers, central policy/identity, durable jobs, broader integrations | Only when multi-team demand is measured. |

The first two phases are expected to require roughly 6-10 engineer-weeks, plus AppSec
labeling and review capacity. Enterprise integrations, high-assurance sandbox operation,
and corpus preparation can be the longer path.

## Outstanding Decisions for Leadership

These decisions should be made before or during Phase 0. They shape cost, risk, and
the useful scope of the pilot.

| Decision | Why it matters | Recommended starting position |
|---|---|---|
| Pilot workflow and repositories | Determines value, labels, data access, and evaluation relevance | One imported-finding/SARIF triage workflow and a small set of representative, authorized repositories. |
| Accountable owners and review authority | Prevents ambiguous security decisions | Name engineering owner, AppSec approval owner, repository owners, and incident/SRE contact. |
| Provider/data terms | Governs what source/context can be sent to OpenAI or Anthropic and retained | Approve providers per data class; begin with minimum excerpts, local artifacts, and documented retention settings. |
| Model access and budget | Closed-model capability and cost vary by access tier | Start with two approved providers, per-run caps, and escalation only for high-impact ambiguity. |
| Sandbox platform | Determines whether future validation is credible and supportable | Rootless OCI for review; evaluate `abox` as an optional microVM agent-worker backend, then select a supported gVisor/Kata/microVM path before active execution. |
| Network enforcement and response | Passive logs cannot contain a malicious dependency or agent | Require default-deny worker networking, an independently validated host-side collector, a narrow inference broker, and an on-call/quarantine path before any execution. |
| Dependency and integration budget | Prevents the harness from becoming a new supply-chain and credential risk | Approve a minimal pilot allowlist; require the integration-admission controls above and a measured value case for every exception. |
| Context sources | Strong context improves decisions but expands data exposure | Start with catalog, artifact/deployment metadata, API contracts, SBOM/VEX, and approved invariants; defer broad IAM/log ingestion. |
| Human decision rights | Defines what can be automated safely | Human approval for high-impact closure, suppression, patch export, external writes, and all active testing. |
| Evaluation corpus and benchmark rights | Determines credible promotion decisions and legal use | Build a private labeled corpus; admit public tasks through the benchmark registry with artifact-level rights review. |
| Deployment and operating model | Controls cost and administrative burden | Single-tenant CLI/dedicated worker first; delay service/UI/gateway work until scale is demonstrated. |
| Success threshold and stop condition | Avoids expanding based on anecdote | Predefine quality, safety, analyst-time, cost, and rollback thresholds before pilot execution. |

## Recommendation

Approve Phase 0 and Phase 1 for a bounded, read-only pilot. Fund the minimal team
needed to own the harness, AppSec evaluation, and sandbox/platform review. Do not fund
active validation, a shared multi-tenant service, or a training program until the pilot
shows measured value and clears the safety and governance gates.

## Related Detail

This is the management overview. Supporting material is maintained in:

- [Research overview](research/README.md)
- [Reference architecture](research/reference-architecture.md)
- [Context and safe validation](research/context-and-safe-validation.md)
- [Evaluation and gym design](research/evaluation-and-gym.md)
- [Implementation plan](research/implementation-plan.md)
- [Rust alternative proposal](rust_proposal.md)
- [Rust alternative implementation plan](rust_implementation_plan.md)
