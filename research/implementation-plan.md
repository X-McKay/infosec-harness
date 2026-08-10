# Implementation Plan

## Outcome

Deliver Proposal 1 as a bounded, single-tenant Python pilot that can safely triage
imported findings and review authorized source snapshots. It must prove value against
the current AppSec workflow before adding deeper discovery, active validation, shared
service infrastructure, or model-training work.

The plan has two equal outputs:

1. A usable evidence-first harness with OpenAI and Anthropic adapters, deterministic
   policy, cost controls, and human review.
2. A measurement system that can answer whether it is safer, more accurate, faster,
   and cheaper than the baseline.

The detailed architecture, context, sandbox, and evaluation rules remain normative:
[Reference architecture](reference-architecture.md),
[External context and safe issue validation](context-and-safe-validation.md), and
[Evaluation and gym](evaluation-and-gym.md).

## Planning assumptions

- Initial scope is one AppSec-owned workflow: imported SARIF/backlog triage and
  read-only repository review. Discovery and dynamic validation come later.
- The pilot has a named engineering owner, AppSec reviewer, and repository owners for
  the first representative systems. SRE/infra ownership is required before a validation
  range is built.
- The initial data plane is local encrypted storage and a single tenant. Central queue,
  gateway, and multi-tenant UI work belong to Proposal 2.
- Every automation result is advisory until the evaluation and safety gates below pass.
- The pilot has a strict dependency and integration budget. New runtime services,
  agent frameworks, MCP servers, skills, shared retrieval/memory stores, and provider
  gateways are excluded unless they pass the admission standard below. `abox` is the
  named exception because it is owned and maintained by the harness team, but it still
  runs behind the same sandbox contract and tests.
- Estimates are engineering increments, not calendar promises. A complete pilot is
  roughly 6-10 engineer-weeks plus AppSec labeling/review time; corpora, enterprise
  integrations, and high-assurance infrastructure can dominate the critical path.

## Workstreams

| Workstream | Scope | Accountable role | Done when |
|---|---|---|---|
| Domain and policy | Pydantic schemas, signed authorization, state machine, evidence/artifact model | Harness engineer + AppSec | Invalid states and unauthorized actions are rejected in tests |
| Provider/runtime | OpenAI, Anthropic, fake/replay adapters, bounded workflow and budgets | Harness engineer | Both providers pass the same contract suite |
| Containment | No-exec analysis sandbox, then separately approved validation range | Security/platform engineer | Negative reachability and teardown tests pass |
| Context | Read-only bundle, fact provenance, initial source adapters | AppSec + platform owner | Threat and finding claims cite fresh facts or explicit gaps |
| Telemetry/economics | Run events, cost ledger, value metrics, summaries | Harness engineer + AppSec ops | Per-run cost/quality/safety report is reproducible |
| Evaluation | CI tests, benchmark registry, private corpus, Inspect adapter, graders, and release gates | AppSec evaluation owner | Held-out suite measures quality and safety with intervals |
| Improvement | Experiment registry, replay, routing/prompt/context changes | Evaluation owner | Changes promote only through preregistered gates |
| Remediation | Evidence export, owner review, patch/deploy verification records | AppSec + repo owner | Validated issue can be tracked to verified remediation |

## Dependency and Integration Admission

The harness's first security boundary is its small trusted computing base. Prefer a
small amount of owned, typed policy code and direct official SDKs over a general
framework, gateway, marketplace, daemon, or plugin ecosystem. An integration is not
admitted because it is popular or convenient.

The pilot runtime allowlist is limited to the Python standard library, Pydantic, direct
official OpenAI and Anthropic SDKs, the selected local sandbox backend, and explicitly
approved deterministic analyzers invoked through the tool broker. SQLite is part of the
Python runtime. `Inspect` is an evaluation-only dependency and must not be on the
production execution path. `abox` is an owned optional sandbox backend; its binary,
guest image, kernel, policy, and proxy configuration are pinned and tested as one
release bundle.

All other dependencies, external tools, containers, services, and adapters require a
written admission record with:

1. A specific pilot workflow gap and a preregistered quality, safety, or cost metric.
2. An explanation of why the existing controller, direct SDKs, deterministic tools, or
   standard library cannot meet that need.
3. A named internal owner, maintenance/patching plan, license and data-use review,
   immutable version/digest, SBOM, and vulnerability-monitoring path.
4. A threat model covering credentials, egress, code execution, data retention,
   configuration/instruction injection, tenancy, failure modes, and removal.
5. Offline/replay tests, a sandbox/egress profile, rollback plan, and a proof that the
   integration does not obtain ambient authority.
6. A development-corpus experiment showing material benefit that exceeds the added
   attack surface, operational burden, and maintenance cost.

Unknown, dynamically installed, repository-controlled, or runtime-downloaded
integrations fail closed. Production jobs never install packages, fetch skills/rules,
pull images, or contact registries; they consume a signed dependency closure prepared
outside the job. Any exception is version-scoped, time-bounded, auditable, and
revocable.

## Delivery increments

### Increment 0: mobilize and define the baseline

**Goal:** make the pilot measurable before writing an agent loop.

Deliverables:

- Name the owner, approvers, incident contact, data classifications, repository scope,
  and explicitly excluded environments/actions.
- Publish an initial authorization manifest, reviewed provider/data-retention policy,
  incident-handling runbook, and retention schedule.
- Capture the human baseline for 20-50 representative findings: reviewer minutes,
  disposition, severity, evidence, remediation state, and uncertainty.
- Freeze the first development and held-out task sets. Split by repository and time;
  no task or close clone may appear in both sets.
- Publish a benchmark-admission record for each external suite: intended decision,
  task subset, source/harness/data/image licenses, exact revision/image digests,
  known contamination or grader risks, data classification, access tier, required
  containment profile, and accountable owner. Do not pull an entire public suite
  merely because it is available.
- Publish the initial runtime dependency allowlist, owner, pinned version/digest,
  license, update cadence, and removal path. Treat every dependency change as a
  security-sensitive configuration change with an SBOM and reviewable diff.
- Define first release thresholds for high-severity false dismissal, policy violations,
  maximum run cost, and minimum analyst-time/value improvement. AppSec owns the numeric
  bounds because they are risk decisions, not model defaults.
- Define the initial `EgressPolicy`, `NetworkEvidence`, and automated-containment
  contracts. The pilot has zero permitted unobserved or unauthorized external flows;
  name the incident/on-call owner and retention policy for flow evidence.

Exit evidence:

- A signed scope and data-use record exists for every pilot task.
- The baseline has dual review plus adjudication for high-impact labels.
- Every admitted external task is assigned to a defensive, research, or high-risk
  capability lane. The latter cannot be scheduled by ordinary CI or product releases.
- The release gate and rollback owner are written before model selection.
- The runtime contains no unapproved service, extension, runtime download, or ambient
  credential path.

### Increment 1: reproducible kernel and no-exec triage

**Goal:** produce evidence-backed triage without executing target-controlled code.

Build:

- Python 3.12 project scaffold with `mise`, `uv`, `just`, `prek`, pinned dependency
  lock, CI, and secret/dependency checks.
- Minimal production dependency groups: direct official SDKs and schema/runtime
  libraries only. Keep evaluation, scanner, and sandbox integrations in separate
  optional groups; do not import them on the normal triage path.
- Versioned Pydantic schemas for authorization, task, budget, finding, evidence,
  disposition, `SecurityContextBundle`, run record, and policy decision.
- Local explicit state machine: ingest -> preflight -> triage -> adjudication ->
  review-required -> complete, with classified terminal states.
- Official OpenAI and Anthropic adapters behind `ModelBackend`, plus fake/replay
  backend. Record effective model/version, access tier, request ID, usage, and policy
  stop without persisting hidden reasoning.
- SARIF import that preserves rule metadata, locations, code flows, fingerprints,
  suppressions, scanner provenance, revision, and coverage.
- Typed read/search/tree tools and rootless no-exec sandbox with network disabled,
  read-only source, quotas, canonical paths, no host credentials/socket/home.
- A sandbox-independent network control plane. No-exec jobs have no NIC or external
  route. The default keeps model calls in the controller and uses the guest only for
  typed tools. Any exceptional guest-side model path is a task-scoped local inference
  broker, never a general proxy: it validates destination, TLS name, method/path,
  request/response size, rate, and budget while holding provider credentials outside
  the guest.
- Host-side network collection keyed by run, guest/cgroup, process, policy and target
  manifest. It records DNS and connect attempts, resolved IPs, TLS/HTTP metadata,
  bytes, verdicts, and enforcement health without persisting prompt or source bodies.
  Missing collector coverage or a flow without a policy decision fails the run closed.
- Bounded `EvidenceSlice` builder that combines SARIF code flows, deterministic
  source/tree search, approved configuration facts, and analyzer output into a typed
  model view. It records omitted surfaces and provenance without a graph/RAG,
  vector-store, memory, document-parsing, or MCP dependency.
- Content-addressed artifacts, SQLite metadata, JSONL audit, deterministic report, and
  human disposition export.

Initial commands:

```text
just check
just test
just sandbox-self-test
just network-self-test
just triage SARIF TARGET REVISION
just cost-report RUN_ID
```

Exit evidence:

- Fake and live low-risk provider contract tests pass.
- A malformed model response, policy-blocked tool request, timeout, and provider
  refusal all yield different recorded states.
- Every report cites immutable source/evidence artifacts and cannot auto-close a
  high/critical finding.
- Dependency-closure tests prove the triage path cannot trigger package installation,
  container/image download, plugin/skill discovery, registry access, or unapproved
  subprocess execution.
- Network self-tests prove denial of external DNS, IPv4/IPv6, metadata, registries,
  CI/artifact services, host bridges and provider-direct connections; they also prove
  that the independent collector observes a known allowed and denied synthetic flow.

### Increment 2: telemetry, cost ledger, and value baseline

**Goal:** make every run explainable in quality, safety, time, and money.

Build the event and metric pipeline in parallel with Increment 1. It must be part of
the controller, not an after-the-fact log parser.

Required event classes:

| Event | Required fields |
|---|---|
| `run_started` / `run_finished` | run/task/config/policy/context hashes, actor, workflow, terminal state, timestamps |
| `dependency_closure_verified` | closure/SBOM/policy hashes, component digests, admission IDs, signature result, prohibited-download checks, sandbox image/profile |
| `stage_started` / `stage_finished` | stage, budget reservation/consumption, duration, candidate counts, coverage |
| `provider_request` / `provider_result` | provider/model/access tier, request class, input/output/cache/reasoning tokens, latency, retry, request ID, classified error, actual/estimated cost |
| `tool_requested` / `tool_decided` / `tool_finished` | typed action, normalized arguments hash, policy decision ID, sandbox/profile, duration, bounded result hash, exit/error class |
| `network_decided` / `network_observed` | run/guest/process identity, policy/rule ID, protocol, DNS name or destination identity, resolved IP/port, TLS/HTTP metadata, direction, bytes, verdict, collector health; redact payloads and provider request bodies |
| `network_contained` | triggering event/rule, kill and lease-revocation timestamps, quarantine/artifact references, observer status, human-alert result |
| `unexpected_secret_discovered` | restricted evidence fingerprint/classification, discovery surface, redaction result, stop/quarantine decision, human credential-response reference; it is never made usable by a tool or model |
| `context_collected` / `context_viewed` | connector/query version, claim IDs, classification, freshness, gaps/conflicts, byte/record count |
| `finding_state_changed` | stable finding/root-cause ID, evidence hashes, validation/coverage/disposition state, reviewer and reason code |
| `remediation_state_changed` | patch/test/deployment artifact, owner, review time, verified-remediation result |
| `safety_event` | policy/egress/secret/canary/grader/teardown event, severity, containment outcome |

Privacy and retention rules:

- Default to IDs, hashes, classifications, counts, and redacted excerpts. Raw source,
  prompt, tool output, credential material, and customer data are separate protected
  artifacts with explicit retention and access policy.
- Never send telemetry to a third party by default. Start with local JSONL plus SQLite
  and map stable fields to OpenTelemetry only after a data review.
- Preserve all policy/safety events; sample only low-risk performance events. Partition
  all caches and records by tenant, repository, data class, and context bundle.

Cost ledger:

1. Load a dated, reviewed provider price/capability catalog.
2. Estimate worst-case cost at preflight and reserve the narrowest applicable budget:
   organization, tenant, repository, workflow, run, stage, and finding.
3. Record token/cached-token/tool/sandbox/storage costs as they occur and stop on hard
   token, call, time, tool, concurrency, and dollar limits.
4. Reconcile provider-reported usage and invoices into an immutable cost adjustment;
   do not silently overwrite the original estimate.
5. Attribute shared fixed costs separately from marginal run cost. Report both.

Exit evidence:

- A run report reconciles estimate, reservation, observed usage, and final cost by
  stage/model/finding.
- A forced retry storm, stale price catalog, and provider usage mismatch fail safely.
- Redaction, retention, and access tests prove telemetry cannot become a source or
  credential leak.

### Increment 3: comprehensive test and evaluation foundation

**Goal:** establish a release gate before expanding autonomy or tool authority.

Implement the following test pyramid:

| Layer | Runs when | Examples |
|---|---|---|
| Unit/schema | Every change | parsing, migrations, budgets, cost allocation, state transitions, root-cause matching |
| Provider contract | Every change; scheduled live smoke | structured output, tools, errors, usage normalization, access-tier rejection |
| Policy/property | Every change | path/symlink/argv fuzzing, approval expiry, DNS/redirect scope, budget monotonicity |
| Sandbox integration | Every change on capable runner | no egress, metadata, host socket/home, engine, provider key, process leak, output flood; independent collector coverage and kill/revocation latency |
| Adversarial harness | Every change | poisoned source/SARIF/docs, secret canaries, malicious archives, prompt injection, grader/answer discovery, cache/proxy/helper escape and callback attempts |
| Workflow evaluation | Nightly/release | private triage, discovery, context, threat-model, patch, and validation cases |
| Public smoke | Scheduled | pinned OWASP Benchmark and selected Inspect defensive tasks; Cybench/CVE-Bench only in an approved isolated research lane |
| High-risk capability research | Manually approved campaign | Fixed ExploitGym/Cybench/CVE-Bench subset, independent oracle, microVM teardown, and containment-escape review |
| Shadow/review | Before promotion | blind reviewer comparison, high-impact dismissal review, remediation follow-up |

Build a `BenchmarkRegistry` and an evaluation-lane runner alongside the test pyramid.
The registry is the source of truth for what may be executed, rather than an arbitrary
task name passed to a CI job. Each immutable entry records the suite/task ID and split,
repository and evaluator revision, source/data/image licenses, image and dependency
digests, task inputs, hidden-grader location, oracle and known-clean self-test results,
architecture/runner requirements, data classification, model-access tier, approved
network profile, budget, expiry/revalidation date, and owner approval. Preserve task
and grader changes as new entries; do not overwrite a released result's manifest.

Implement these lanes in order:

| Lane | Initial suites | Automation level | Purpose and policy |
|---|---|---|---|
| `regression` | Harness-owned fixtures, selected OWASP Benchmark and CyberSecEval 4 cases | Every change or scheduled | Schema, policy, prompt-injection, and false-positive regression. No target execution or unpinned downloads. |
| `release` | Private chronological, repository-disjoint triage, context, threat-model, and remediation corpus | Nightly and candidate release | The only product-promotion quality gate. Agent cannot access hidden graders, holdout records, prompt-search indexes, or optimization data. |
| `defensive_research` | PrimeVul, selected SEC-bench patch tasks, and approved CyberGym-E2E/CyberGym or CVE-Bench tasks | Scheduled, owner-approved | Generalization, evidence, patch, and cost studies. Use pinned images in a disposable range with independent oracle checks. Results inform design but do not override the private release gate. |
| `high_risk_capability` | Fixed ExploitGym, Cybench, and exploitation-task subsets | Manual research campaign only | Measure exploit capability and containment resistance. Requires the Increment 5 range; no ordinary CI, product credential, production connection, or automatic promotion path. |

Use `Inspect` as the common outer runner where it supports the suite, but keep the
harness-owned policy broker, manifest validation, telemetry, and sandbox profile in
control. Public tasks have known-answer, public-writeup, and evaluator-loophole risk:
run an oracle, known patch/reproducer, and known-clean control before accepting any
score, and classify grader or infrastructure faults separately from task failures.

#### License and rights controls

Track rights independently for each artifact class; a benchmark's top-level repository
license does not automatically cover its task data, upstream source snapshots, Docker
or VM images, packages, advisories/reports, exploit fixtures, generated outputs, or
the hosted-model service used to run it. For example, ExploitGym's harness is
Apache-2.0 while its bundled tasks retain their respective upstream licenses. Treat
model-provider contracts, enterprise source-data agreements, confidentiality, export,
and data-residency restrictions as adjacent use rights even though they are not OSS
licenses.

The registry must record, per artifact and materialized derivative, the upstream URL
and revision/digest, license identifier or terms reference, attribution/notice file,
rights holder where known, permitted purpose, redistribution/hosting/training limits,
geography/data-class constraints, review date, expiry, and counsel/owner decision.
Use explicit states: `approved_internal_eval`, `approved_with_obligations`,
`needs_review`, `prohibited`, and `unknown`. Only an approved state may materialize an
artifact or start a run; `approved_with_obligations` must attach required notices,
isolation, retention, and access controls to the run manifest. Unknown or ambiguous
rights fail closed.

Operational consequences:

- Store upstream notices and an SBOM with the immutable task manifest. Do not publish
  benchmark images, full source snapshots, prompts, transcripts, exploit artifacts, or
  modified task bundles to an internal registry, a public leaderboard, or a customer
  unless the specific artifact rights permit it.
- Separate permission to execute an artifact internally from permission to redistribute
  it, offer it as a hosted service, train/fine-tune on it, or retain it in traces. A
  permissive Python harness does not resolve obligations inherited from a bundled
  target or dataset.
- Pin and archive the relevant license/terms text and access date with the digest;
  upstream repositories, datasets, and provider terms can change after admission.
- Route copyleft, non-commercial/research-only, bespoke, missing, or conflicting terms
  to legal/procurement review. The harness records and enforces the decision but does
  not make legal determinations.
- Keep private source and context bundles in a stricter class than public benchmark
  data. Provider/data-processing approval is separately required before any excerpt
  is sent to a model, regardless of the benchmark's license.

Evaluation governance:

- Every task has immutable source/target/image/context references, authorization,
  budget, allowed tools, hidden grader, oracle self-test, known-clean control, and
  license/sensitivity record.
- The task author, model tuner, and final evaluator must not be the sole adjudicator of
  high-impact outcomes. Keep a changelog of task and grader fixes.
- Run at least three trials per development case and use clustered bootstrap intervals
  by task. Compare policies through paired experiments when the same tasks are run.
- Treat provider refusal, policy block, sandbox error, grader error, and budget
  truncation as distinct outcomes. Do not score them as a false positive or a model
  failure by default.

Exit evidence:

- Oracle, known-vulnerable, and known-clean runs prove each active task and grader.
- The private held-out suite is technically inaccessible to prompt search, tuning, and
  gym/reward data pipelines.
- Safety regression suite is a hard gate with zero permitted unauthorized or
  unobserved egress, secret access, scope expansion, or grader tampering.
- Registry admission tests reject missing licenses, unpinned images, absent oracle or
  clean-control evidence, an expired approval, or a high-risk task sent to CI/release
  infrastructure.
- Registry admission tests also reject an unknown/prohibited rights state, absent
  attribution obligations, expired provider/data approval, or an attempted export,
  reuse, or training action outside the artifact's recorded permission.
- Supply-chain regression tests reject an unapproved dependency, changed lockfile or
  sandbox image without admission metadata, runtime download attempt, unsigned
  closure, direct egress from an integration, or ambient credential access.

### Increment 4: context-aware triage and repository review

**Goal:** improve relevance and severity without exposing enterprise systems to the
model.

Build:

- `SecurityContextBundle` store and a prompt-view compiler with provenance, freshness,
  contradictions, coverage gaps, and field-level classification.
- Initial read-only adapters chosen for actual pilot value: service catalog/ownership,
  deployment/artifact inventory, API contracts, SBOM/VEX, and owner-approved business
  invariants. Add cloud/IAM/telemetry sources only after access and data review.
- Typed, brokered context questions. The model never sends live SQL/KQL/GraphQL,
  arbitrary cloud CLI requests, or connector credentials.
- Threat-model workflow that cites facts or records assumptions/questions, and triage
  workflow that records configuration/deployment evidence separately from code.
- Coverage-aware comparison across snapshots: new, persisting, reopened,
  resolved-with-proof, and unknown.
- Defer graph/RAG retrieval and PDF ingestion entirely from the pilot. An optional
  `CodeContextBackend` or `DocumentIngestor` may be proposed only through the
  integration-admission process after a measured baseline gap exists; neither is a
  roadmap commitment. Do not add an MCP server, shared graph/vector database,
  auto-installed hook, repository-controlled instruction, document service, or parser
  dependency by default.

Exit evidence:

- Tests cover stale/contradictory/poisoned facts, permission gaps, source identity
  collisions, and cross-tenant cache isolation.
- Expert review shows context improves a preregistered outcome, such as severity
  calibration, false-positive precision, or triage time, without regressing high-risk
  recall.

### Increment 5: bounded discovery and safe validation lab

**Goal:** validate actionable hypotheses in a production-free environment.

Prerequisites: all prior safety gates pass; named SRE/platform owner exists; a signed
rules-of-engagement process and incident response path are operational.

Build:

- Separate `ValidationPlan`, `TestTargetManifest`, action catalog, oracle registry,
  approval, health, kill-switch, and teardown records.
- Separate agent guest and synthetic target range with a microVM/Kata/gVisor-class
  backend appropriate to risk. No plain-container fallback for target-controlled code.
- Offline target/execution episode: a signed dependency closure is attached read-only.
  Registry/cache, CI, artifact store, browser/request-capture, answer store, metadata,
  enterprise, and public network paths are denied and independently observed. When an
  approved closed model is needed, the worker may reach only a task-scoped inference
  broker over a fixed local or allowlisted channel; the broker holds credentials,
  enforces schema/byte/cost limits, and offers no general proxying or shared-service
  access. The guest never receives provider credentials.
- A signed, expiring `EgressPolicy` permits only declared worker-to-broker or
  worker-to-synthetic-target edges. A host/hypervisor-side collector records every
  attempted and allowed flow. DNS rebinding, IPv4/IPv6 divergence, proxy tunnelling,
  raw sockets, registry/CI/metadata reachability, unapproved destinations, missing
  telemetry, or quota breach automatically kill the worker, revoke its lease, and
  create a quarantined safety event.
- Negative-reachability drills from both the worker and compromised synthetic target
  prove they cannot reach controllers, graders, artifact/package caches or proxies,
  CI helpers, request-capture services, neighboring workloads, enterprise networks,
  or the public Internet. “No direct Internet” does not pass this gate by itself.
- Synthetic data/identities and local fakes for IdP, data stores, queues, payments,
  webhooks, DNS, cloud metadata, and callbacks.
- Deterministic out-of-band oracles, vulnerable/clean differential controls where
  practical, target health checks, network circuit breaker, and destructive teardown.
- Terminal credential-quarantine workflow. Discovered credentials are redacted,
  fingerprinted, removed from agent-visible artifacts, and routed to human response.
- After the lab passes its containment drills, implement a separate research-campaign
  controller for approved high-risk benchmarks. It accepts only a signed,
  short-lived `BenchmarkRunManifest` derived from a registry entry; it provisions a
  dedicated account and microVM-class worker, permits only the task-scoped inference
  broker, blocks all other shared control services and egress, and destroys all
  worker/target state after independent scoring. Start with a very small ExploitGym or
  Cybench subset. Do not expose benchmark target selection, downloads,
  firewall/proxy configuration, or scorer internals to the model.

Exit evidence:

- Containment tests prove negative reachability from both worker and compromised target
  to every excluded shared service and neighbor workload.
- Every dynamic finding is `reproduced`, `supported`, `not_reproduced`, `invalidated`,
  `not_applicable`, `inconclusive`, `environment_mismatch`, `policy_blocked`,
  `authorization_failed`, `infra_error`, or `cleanup_failed`; no result is collapsed
  to a false positive without counter-evidence.
- Kill, lease-revocation, and teardown drills complete within the AppSec/SRE-approved
  window and detect residual state.
- A high-risk benchmark dry run proves the worker and compromised target cannot reach
  package registries, artifact/cache services, CI, browser/request-capture systems,
  provider credentials, hidden answers, enterprise systems, or neighbor workloads.

### Increment 6: pilot, shadow mode, and remediation loop

**Goal:** demonstrate operational value on real authorized work while keeping human
control over consequential decisions.

Operate the selected repositories in shadow mode first. The harness emits evidence
packs and proposed dispositions; current AppSec process remains the authority. For
confirmed issues, create a remediation record that joins the finding, patch proposal,
security/regression tests, owner review, deployment artifact, and post-deployment
verification.

Cadence:

- Per run: automated safety/cost/coverage/evidence summary.
- Weekly: quality, reliability, spend, top blockers, and remediation aging review.
- Biweekly: paired model/prompt/tool/context experiments on development tasks only.
- Monthly: release-gate assessment, corpus health review, label adjudication, and
  incident/exception review.

Exit evidence:

- Held-out quality and safety gates pass with confidence intervals, not point metrics.
- Reviewers agree that evidence packs reduce, rather than shift, investigation work.
- At least one representative remediation is tracked to a verified deployed artifact.
- Rollback to the prior approved configuration has been exercised.

## Metrics and decision rules

### Safety and containment

These are guardrail metrics, not optimization targets. Any release candidate with a
nonzero critical policy breach fails promotion pending investigation.

| Metric | Definition | Target use |
|---|---|---|
| Unauthorized action rate | disallowed tool dispatches / requested actions | Must be zero for executed actions |
| Unexpected egress rate | connections/DNS/proxy interactions outside target manifest / episodes | Must be zero |
| Network observer coverage | observed connection attempts with a matching policy decision / all attempts | Must be 100%; missing coverage fails closed |
| Unknown-flow rate | observed flows without a policy decision or accountable process identity / episodes | Must be zero |
| Deny-to-containment latency | time from deny/trigger to worker kill and lease revocation | Release gate; alert on any missed containment |
| Secret/canary exposure rate | provider/log/agent/target exposure events / runs | Must be zero |
| Sandbox containment pass rate | successful negative reachability checks / checks | Release gate |
| Teardown residual rate | runs with remaining process/network/data/lease state / dynamic runs | Release gate |
| Grader integrity events | answer, scorer, reward, or metadata access attempts | Hard failure and corpus review |
| Benchmark-manifest violations | runs started with a stale, altered, unapproved, or lane-incompatible task manifest / attempted runs | Must be zero |
| Unapproved dependency activation rate | unapproved package, image, plugin, skill, service, or runtime download activations / runs | Must be zero |

### Quality and evidence

Report by workflow, severity, CWE family, language, and repository class. Do not lead
with accuracy on imbalanced data.

| Metric | Definition |
|---|---|
| Precision | accepted true positives / accepted findings |
| Recall / TP retention | recovered known positives / known positives; report confidence bounds |
| False-dismissal rate | known positives closed or suppressed incorrectly / known positives |
| Evidence validity | accepted findings with independently valid evidence / accepted findings |
| Correct disposition | reviewer-adjudicated matching disposition / evaluated findings |
| Coverage | examined surfaces and rule/target coverage relative to authorized plan |
| Calibration | Brier score/ECE and abstention behavior against reviewer labels |
| Reproduction quality | valid oracle or supporting-proof rate, separated from failed/ineligible attempts |
| Patch quality | security and functional regression pass rate, then deployed verification rate |

### Cost, latency, and reliability

| Metric | Definition |
|---|---|
| Cost per run/stage/finding | reconciled marginal provider, tool, sandbox, and storage cost |
| Cost per verified TP | total marginal cost / independently accepted true positives |
| Cost per correct disposition | total marginal cost / reviewer-confirmed triage decisions |
| Budget utilization | actual / reserved cost, tokens, calls, wall time, and tool calls |
| Time to first evidence | start to first valid supporting/counter-evidence artifact |
| Time to disposition | start to reviewer-adjudicated decision |
| Provider/sandbox reliability | classified provider, policy, timeout, sandbox, and grader failures by attempt |
| Marginal escalation value | quality gain from stronger model/extra attempt/second verifier divided by added cost |

### Value and remediation

Never claim value from raw finding count. Compare against a matched historical or
shadow baseline, and include reviewer time plus infrastructure costs.

| Metric | Definition |
|---|---|
| Validated findings per analyst-hour | accepted unique findings / combined harness-review human time |
| Triage time saved | baseline adjudication minutes minus harness-assisted minutes, sampled and reviewer measured |
| High-risk exposure addressed | severity/business-weighted confirmed issues with verified remediation |
| Time to verified remediation | validated finding to deployed artifact plus successful post-deploy check |
| Remediation aging | confirmed issues without owner/patch/review/deployment by age band |
| Review burden | evidence-return, inconclusive, and false-positive minutes per workflow |
| Net value frontier | quality and risk reduction at a fixed total cost and reviewer-hour budget |

### Metric safeguards

- Stratify and publish denominators. Ten true positives in one high-risk repository do
  not justify a global precision claim.
- Track uncaptured likely positives and unreviewed outputs as unknown, not negatives.
- Record label confidence, reviewer disagreement, and drift. Re-adjudicate samples.
- Use bootstrapped intervals and paired comparisons. A small point improvement with a
  wide interval is an experiment, not a promotion.
- Predeclare the primary metric and stopping rule for an experiment. Do not tune until
  a favorable slice appears.

## Run summaries and dashboards

Generate a machine-readable `RunSummary` plus concise Markdown/JSON report at every
completion. It should contain:

```text
identity:       run, authorization, target snapshot, context, policy, config, dependency-closure hashes
outcome:        terminal state, coverage/deferred surfaces, findings by disposition
evidence:       supporting/counter/proof-gap counts and validation/oracle results
safety:         policy denials, network flow/observer/containment, canary/secret/teardown events
economics:      estimate, reservation, actual/reconciled cost by stage/model/finding
operations:     duration, retries, provider/tool/sandbox/grader error classes
remediation:    owner, patch/test/deployment/post-deploy state and aging
comparison:     prior snapshot/root-cause status and baseline delta when available
next action:    review, evidence request, validation eligibility, or no-action reason
```

Provide four views, initially as generated reports rather than a new web application:

1. **Run view:** evidence, coverage, policy decisions, cost, and recommended human
   next action.
2. **Quality view:** precision/recall/false-dismissal/calibration and label health by
   workflow/CWE/severity.
3. **Safety/reliability view:** containment, policy blocks, provider/sandbox errors,
   observer coverage, unknown-flow count, deny-to-containment latency, incident
   signals, and release-gate status.
4. **Value view:** spend, reviewer time, correctly adjudicated work, remediation aging,
   and marginal value of escalation.

JSONL/SQLite remains the system of record for the pilot. Export only redacted,
authorization-filtered events to an internal OpenTelemetry/metrics backend when it is
needed for cross-run aggregation.

## Improvement and promotion loop

### Configuration change process

Treat model, prompt, tool schema, context builder, routing rule, budget, action
catalog, sandbox image, grader, or policy change as a versioned configuration change.

1. Write a hypothesis, affected workflows, expected benefit, primary metric, safety
   constraints, budget, development task set, and rollback condition.
2. Run unit/contract/sandbox safety tests and oracle self-tests.
3. Run paired, repeated development evaluations with the old configuration.
4. Review failures by stage before proposing another change. Do not compensate for a
   weak grader or missing context by increasing model autonomy.
5. Run untouched held-out and safety suites only for a candidate configuration that
   clears development thresholds.
6. Shadow the candidate on authorized production-like work without changing external
   disposition or remediation.
7. Promote a signed configuration bundle only if capability, safety, cost, latency,
   false-dismissal, and reviewer-effort gates all pass. Otherwise retain the baseline
   and record the result.

### Improvement order

1. Fix task ambiguity, broken graders, missing evidence, or unsafe tools.
2. Improve deterministic retrieval, context selection, schemas, and stopping rules.
3. Optimize model routing, effort, attempt count, and escalation under fixed policy.
4. Add curated examples from expert/programmatically validated trajectories.
5. Consider provider fine-tuning or open-weight SFT/preferences only when the data,
   holdout, and governance requirements are met.
6. Consider sandboxed RL only for approved open weights and purpose-built gym tasks.

Production runs never update prompts, policies, tools, model weights, or access tiers.
The gym records trajectories and evaluates controller choices first; it is not a live
self-modification mechanism.

## Promotion gates and stop conditions

| Gate | Required evidence | If it fails |
|---|---|---|
| Scope/data | valid authorization, provider/data policy, retention decision | Do not start |
| Containment | negative reachability, independent network-observer coverage, secret, teardown, and kill-switch tests | Disable execution; investigate |
| Quality | held-out precision/recall/false-dismissal/calibration thresholds | Keep advisory/shadow mode |
| Economics | cost cap and positive quality/value frontier versus baseline | Reduce scope/routing or stop |
| Operations | reliable provider, sandbox, artifact, and audit behavior | Fix infrastructure before scaling |
| Remediation | owner review and verified patch/deployment evidence | Do not claim risk reduction |
| Governance | signed configuration, reviewer approval, rollback evidence | Do not promote |

Move from Proposal 1 to Proposal 2 only when measured concurrency, durable jobs,
centralized identity/retention, or shared range capacity are genuine bottlenecks. Move
to Proposal 3 only when a dedicated research program needs large isolated campaigns,
private benchmark infrastructure, or approved open-model training.

## First backlog

The first implementation tickets should be small, independently testable, and ordered
to preserve the gates above:

1. Bootstrap Python project, lockfile, `mise`, `just`, `prek`, CI, and test fixtures.
2. Define and test the runtime dependency allowlist, admission record, signed
   dependency closure, SBOM generation, and runtime-download denial.
3. Define domain schemas, serialization, migrations, artifact IDs, authorization, and
   budget policy.
4. Build fake/replay provider and provider contract suite.
5. Add OpenAI and Anthropic native adapters with usage/error normalization.
6. Implement SQLite/JSONL audit and `RunSummary`/cost ledger.
7. Implement SARIF ingestion, deterministic dedupe, `EvidenceSlice`, coverage/proof-gap model, and
   evidence report.
8. Implement `EgressPolicy`, host-side `NetworkEvidence`, automatic quarantine, and
   a fail-closed network self-test before enabling any sandboxed worker.
9. Implement no-exec read/search tools plus rootless containment self-test.
10. Build the benchmark registry, task-manifest validator, and fast `regression` lane
   using owned fixtures plus a small pinned OWASP/CyberSecEval subset.
11. Build balanced internal triage fixtures, graders, reviewer-label workflow, private
   `release` lane, and Inspect adapter.
12. Add initial context-bundle schema and manually curated context fixtures.
13. Run shadow triage baseline, then add only the context connector or model escalation
    that wins on the development suite.
14. Design the validation-plan/oracle/range interface before provisioning a lab.
15. Add active validation only after the signed rules-of-engagement and containment
    drills pass.
16. Admit defensive research suites incrementally, then run a manually approved
    high-risk ExploitGym/Cybench campaign only after the dedicated range proves
    negative reachability and teardown.
