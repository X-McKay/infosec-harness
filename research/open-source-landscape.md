# Open-Source Landscape

## Selection criteria

The recommended stack favors small, replaceable components with clear trust
boundaries. Each dependency was assessed for:

- fit with provider-neutral Python and typed outputs;
- security behavior under hostile repository/tool content;
- ability to preserve provider-specific capabilities;
- reproducible evaluation and sandbox integration;
- license and source-available/enterprise boundaries;
- maintenance activity as of 2026-08-09;
- operational burden relative to a small first release.

Repository activity is a snapshot, not a maintenance guarantee. Licenses must be
checked again at the exact version and for bundled rules, models, images, benchmarks,
and datasets; these often differ from the top-level code license.

## Recommended stack

| Layer | Pilot choice | Later option |
|---|---|---|
| Provider API | Harness-owned protocol plus direct official OpenAI/Anthropic SDK adapters | Pydantic AI adapter; LiteLLM gateway for centralized multi-team routing |
| Agent runtime | Ordinary Python state machine and bounded loop | LangGraph only if durable pause/resume graphs are measured requirements |
| Domain/schema | Pydantic v2 and JSON Schema | Preserve schema regardless of runtime framework |
| Tools | In-process typed Python tools | Carefully approved, sandboxed MCP servers |
| External context | Harness-owned claim graph plus explicit read-only adapters | Existing Backstage, Dependency-Track, Cartography, GUAC, OTel, and OCSF integrations |
| Static evidence | SARIF import plus Semgrep/tool-specific adapters, SBOM and OSV tools | Licensed CodeQL, language-specific analyzers, VEX export |
| Sandbox | Rootless OCI for non-executing review; gVisor/Kata or microVM for target code | Firecracker fleet for multi-tenant/high-risk proof execution |
| Validation fixtures | Synthetic data and in-process/service-specific fakes | Sealed multi-service ranges and disposable cloud accounts |
| Evaluation | Inspect AI, Inspect Cyber, Inspect Evals | NeMo Gym adapter for a funded training program |
| Gym API | Harness-owned typed protocol plus Gymnasium adapter | NeMo Gym / TRL / NeMo RL for accessible open weights |
| Telemetry | Append-only JSONL/SQLite plus redacted OpenTelemetry export | Self-hosted MLflow or Langfuse after a data review |
| Threat model | Internal typed graph and evidence | Threat Dragon import/export; evolving interchange adapters |

## Provider and agent frameworks

### Direct official SDK adapters: recommended core

For two providers, direct adapters have the least hidden behavior and smallest
dependency surface. A local `ModelBackend` protocol normalizes domain needs while a
capability profile exposes differences in tools, structured output, caching, batches,
reasoning controls, data retention eligibility, and error semantics.

This approach costs some adapter maintenance but avoids coupling authorization,
findings, traces, and workflow logic to a framework. A fake/replay adapter provides
deterministic tests. See the protocol in the
[reference architecture](reference-architecture.md).

### Pydantic AI

[Pydantic AI](https://github.com/pydantic/pydantic-ai) is MIT licensed, actively
developed, Python-native, and supports
[OpenAI, Anthropic, and many other providers](https://pydantic.dev/docs/ai/models/overview/).
It offers typed tools/results, dependencies, model selection, usage limits, deferred
approval, eval, MCP, and OpenTelemetry integration. It is the strongest existing fit
if the project prefers a framework.

Tradeoff: the surface and API are moving quickly, and a security harness still needs
its own authorization, sandbox, evidence, and audit contracts. Put Pydantic AI behind
the local protocol so it can be upgraded or replaced without rewriting the domain.

### LiteLLM

[LiteLLM](https://github.com/BerriAI/litellm) provides a broad unified SDK and an
OpenAI-compatible gateway with retries, fallback, virtual keys, spend tracking,
budgets, rate limits, caching, and observability. Code outside its `enterprise/`
directory is MIT; enterprise components have separate terms.

It is valuable in Proposal 2 when centralized credential brokerage, many providers,
and organizational cost control are real needs. For a local two-provider pilot it adds
a fast-moving dependency or a network service, creates a high-value credential/source
data choke point, and can obscure provider semantics. Do not make its response schema
the domain schema or add the proxy merely to switch between OpenAI and Anthropic.

### LangGraph

[LangGraph](https://github.com/langchain-ai/langgraph) is MIT licensed and provides
durable graph execution, checkpoints, and human-in-the-loop control. It is appropriate
when a workflow genuinely pauses for days, resumes across workers, or has many dynamic
branches.

The proposed pilot has a small explicit state machine. LangGraph would add persistence
and a sensitive transcript/checkpoint store without reducing the hard policy or
sandbox work. Defer it until durability requirements exceed ordinary database state.

### NVIDIA NeMo Agent Toolkit

[NeMo Agent Toolkit](https://github.com/NVIDIA/NeMo-Agent-Toolkit) is Apache-2.0 and
offers config-driven workflows, multiple framework integrations, tracing/profiling,
evaluation, and prompt/parameter optimization. It supports OpenAI directly and reaches
Anthropic through providers such as LiteLLM or Bedrock rather than a symmetric direct
adapter.

It is a useful integration for NVIDIA infrastructure or workflow profiling. Its
plugin/config surface and optimizer can increase complexity, cost, and overfitting, so
it should not be a required pilot dependency. NVIDIA's
[vulnerability-analysis blueprint](https://github.com/NVIDIA-AI-Blueprints/vulnerability-analysis)
is more valuable initially as a staged workflow/evidence reference.

### Coding-agent systems

[OpenHands](https://github.com/All-Hands-AI/OpenHands),
[SWE-agent](https://github.com/SWE-agent/SWE-agent), and
[Aider](https://github.com/Aider-AI/aider) are useful baselines for general coding and
security benchmark comparisons. They bring capable repository/shell loops and have
been used in CyberGym or false-positive research.

They are end-user agent products/scaffolds rather than minimal policy kernels. Reusing
one as the production harness would inherit broad shell, context, persistence, and
configuration behavior that still needs containment. Integrate them as eval baselines
or optional workers, not as the authority layer.

[Codex Security](https://github.com/openai/codex-security) is an Apache-2.0,
pre-1.0 CLI and TypeScript SDK for vulnerability discovery, validation, and remediation.
Its sealed scan artifacts, explicit coverage, root-cause comparison, bounded discovery
passes, and separate validation workflow make it a useful optional scanner adapter or
evaluation baseline. It must not replace the Python domain core or isolation boundary:
its [security model](https://github.com/openai/codex-security/blob/main/SECURITY.md)
documents local-account execution and possible ambient credentials, and its validation
workflow can build or execute target-controlled code. Invoke it only in a scrubbed,
externally constrained disposable worker and import its sealed artifacts.

## MCP and tool ecosystems

The official [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk) is
MIT licensed and active. MCP is useful for standard tool discovery and interoperability
but materially enlarges the supply chain and authority surface. The SDK's security
history includes high-severity issues around DNS rebinding, session/principal binding,
task isolation, and WebSocket origin handling; current advisories should be reviewed at
the pinned version. Official
[MCP security best practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
warn that local servers may execute with client privilege.

For the pilot:

- prefer in-process typed tools;
- never dynamically install `npx`, Python, or other MCP packages during a run;
- pre-approve server identity, version/digest, transport, tools, and permissions;
- use stdio or authenticated transports and enforce origin/session binding;
- run the server inside the same or a stricter sandbox;
- give each server/task separate short-lived credentials;
- validate arguments and results and ignore untrusted tool annotations as authority;
- run static/security review before admitting a server or agent skill.

NVIDIA [SkillSpector](https://github.com/NVIDIA/SkillSpector) is an Apache-2.0, young
static/semantic scanner for agent skills and MCP material with SARIF and OSV support.
It is a useful admission signal, not a substitute for provenance review and runtime
containment.

## External context ecosystem

Put a harness-owned context broker between these systems and the model. The broker
owns credentials and reviewed queries, then emits an immutable graph slice with
provenance, freshness, sensitivity, completeness, contradictions, and coverage gaps.
Do not give the model live MCP, SQL, cloud CLI, SIEM, or directory access.

| Source/tool | Recommended use | Caveat |
|---|---|---|
| [Backstage Software Catalog](https://backstage.io/docs/features/software-catalog/) | Consume ownership, system, component, API, and resource declarations if already deployed | Human-governed cache, not exhaustive runtime truth or an authorization system |
| [Dependency-Track](https://docs.dependencytrack.org/) | Organization-wide CycloneDX SBOM/VEX inventory and historical audit decisions | A VEX status remains an issuer assertion; retain evidence and product identity |
| [Cartography](https://github.com/cartography-cncf/cartography) | Optional cloud, Kubernetes, GitHub, Okta/Entra identity and resource graph | Collector output is sensitive; use separate read-only identities and never collect secret values |
| [GUAC](https://github.com/guacsec/guac) | Later cross-artifact SBOM, VEX, provenance, and attestation queries | Useful supply-chain graph, not a complete threat model; some collectors remain less mature |
| [OpenTelemetry semantic conventions](https://opentelemetry.io/docs/specs/semconv/) | Aggregate observed service/deployment edges and operation metadata | Absence of a sampled trace does not prove a path is absent; exclude payloads by default |
| [OCSF](https://ocsf.io/) | Normalize inventory, IAM, activity, finding, incident, and data-security records | Prefer structured fields and bounded evidence to raw, injection-prone log text |
| [CycloneDX](https://cyclonedx.org/specification/overview/) / [SPDX](https://spdx.dev/use/specifications/) | Components, services, dependencies, vulnerabilities, and provenance joins | Bind releases by immutable artifact digest, not mutable version/tag alone |

Cloud inventory APIs and native effective-IAM analyzers are usually stronger sources
than adding a general graph product solely for this harness. Avoid raw Terraform state
by default because it can contain secrets. Avoid enterprise-wide embeddings initially:
they create another sensitive, hard-to-delete copy and make access filtering harder.
See [External context and safe issue validation](context-and-safe-validation.md) for
the connector and claim contracts.

## Sandbox options

### Rootless Podman or Docker

Rootless OCI containers are the easiest reproducible pilot environment and acceptable
for read/search/static-analysis tasks that do not execute hostile target code. Minimum
controls are a read-only root, unprivileged UID, all capabilities dropped,
`no-new-privileges`, seccomp plus AppArmor/SELinux, a workspace-only mount, bounded
`tmpfs`, no engine socket/home/SSH agent/devices, network none or proxy, and strict
PID/CPU/memory/disk/time/output limits.

Containers share the host kernel. They are not by themselves a sufficient boundary
for malicious repository build scripts, fuzzers, exploit payloads, or multi-tenant
execution.

### gVisor

[gVisor](https://github.com/google/gvisor) is Apache-2.0 and provides the OCI-compatible
`runsc` runtime with a user-space application kernel. It is the most practical stronger
local boundary for the pilot. Compatibility and syscall-heavy performance can suffer,
and it remains weaker than a separate guest kernel.

Recommended rule: if a workflow executes target-controlled code, require a configured
gVisor/Kata/microVM backend; otherwise keep the workflow read-only. There is no silent
fallback to a plain container.

### Firecracker and Kata Containers

[Firecracker](https://github.com/firecracker-microvm/firecracker) is Apache-2.0 and
uses KVM microVMs with a separate guest kernel, minimal devices, and a jailer. It is the
preferred high-assurance open-source option for multi-tenant or exploit-capable work.
The cost is Linux/KVM requirements and significant image, network, lifecycle, logging,
and host-hardening operations.

[Kata Containers](https://github.com/kata-containers/kata-containers) combines OCI
workflows with lightweight VMs and is a reasonable cluster-oriented alternative. Both
need an independent security review and properly hardened hosts; a VM label is not a
complete deployment design.

### Softnet for dedicated macOS/Tart hosts

[Softnet](https://github.com/openai/softnet) is a macOS/Tart userspace packet filter,
not a portable sandbox. Its externally controlled, acknowledged, bounded, atomic
policy updates and stateful flow table provide useful egress-enforcer patterns: deny
precedence, explicit rules, and immediate flow invalidation when policy changes.

Do not add it to the pilot's portable core. It is under the
[Functional Source License 1.1](https://github.com/openai/softnet/blob/main/LICENSE),
requires privileged initialization, changes host DHCP behavior, and its default policy
permits globally routable IPv4. If a dedicated Mac/Tart executor is later justified,
wrap it behind an `EgressEnforcer` protocol; only the controller holds its control
socket, policy compilation rejects broad allow rules, and Linux backends implement the
same contract with their native runtime/network controls.

### Validation fixtures and ranges

[Testcontainers Python](https://github.com/testcontainers/testcontainers-python) can
manage ordinary test dependencies, but it is lifecycle plumbing, not a security
boundary; its container-engine socket must never enter the model or target guest.
Useful lab-only fakes include [Moto](https://github.com/getmoto/moto) for selected AWS
APIs, [Azurite](https://github.com/Azure/Azurite) for Azure Storage,
[fake-gcs-server](https://github.com/fsouza/fake-gcs-server) for GCS,
[mock-oauth2-server](https://github.com/navikt/mock-oauth2-server) for test OIDC, and
[WireMock](https://github.com/wiremock/wiremock) or
[Prism](https://github.com/stoplightio/prism) for HTTP/API contracts. Disable any
pass-through mode, use fake credentials, and enforce network denial below the mock.

OWASP [Juice Shop](https://github.com/juice-shop/juice-shop),
[WebGoat](https://github.com/WebGoat/WebGoat), and
[crAPI](https://github.com/OWASP/crAPI) are useful known-vulnerable evaluation targets
inside a private range. They test the harness and oracles; they do not establish
precision on an organization's own applications.

### Hosted and emerging options

[E2B](https://github.com/e2b-dev/E2B) is Apache-2.0 and offers Firecracker-backed
sandbox APIs. It can accelerate a prototype but adds recurring cost, another control
plane/data boundary, and network/telemetry/retention questions. BYOC still needs
operational review.

NVIDIA [OpenShell](https://github.com/NVIDIA/OpenShell) offers declarative default-deny
policy, audit, credential/inference routing, and kernel-level controls. Its official
documentation currently labels it alpha and says not to use it in production. Pilot
it separately; do not make it the production boundary yet.

## Evaluation and gym ecosystem

### Inspect

[Inspect AI](https://github.com/UKGovernmentBEIS/inspect_ai) is MIT licensed, active,
and supports provider-neutral tasks/solvers/scorers, stateful tools, logs, approvals,
parallel eval sets, retries/resume, limits, and pluggable sandboxes.
[Inspect Cyber](https://github.com/UKGovernmentBEIS/inspect_cyber) adds cyber task and
solution-verification conventions, and
[Inspect Evals](https://github.com/UKGovernmentBEIS/inspect_evals) integrates many
public suites.

This is the recommended external evaluation runner. Adapt the harness into an Inspect
solver so production policy remains owned locally. Inspect's sandbox API is plumbing,
not an isolation guarantee; choose and test the backend. Review every upstream
benchmark's code/data/image license and scorer version.

### NeMo Gym and RL stacks

[NeMo Gym](https://github.com/NVIDIA-NeMo/Gym) is Apache-2.0 and expresses environment,
dataset, harness, verifier, per-task state, multi-reward evaluation, and transition to
training. It is closer to language-agent tasks than classic numeric gyms, but its
repository describes evolving early-development APIs. Use it as a future adapter.

[Gymnasium](https://github.com/Farama-Foundation/Gymnasium) is MIT licensed, mature,
and supplies useful `reset`, `step`, `terminated`, `truncated`, seeding, and wrapper
conventions. Add a compatibility wrapper without forcing structured JSON/tool actions
into arbitrary numeric spaces.

[ExploitGym](https://github.com/sunblaze-ucb/exploitgym) is an Apache-2.0 benchmark
harness for developing exploits from known vulnerable inputs, with separately licensed
upstream task data. It currently spans real userspace, V8, and Linux-kernel targets and
ships controller, firewall, and LLM-proxy components. That makes it a useful future
research fixture for testing both exploit capability and containment, not a gym/runtime
dependency or a substitute for false-positive and threat-model evaluation. Its setup
must run in a dedicated high-risk range with an independently enforced egress policy;
the benchmark's own firewall is a useful reference, not the security boundary.

[Hugging Face TRL](https://github.com/huggingface/trl) and
[NeMo RL](https://github.com/NVIDIA-NeMo/RL) are Apache-2.0 post-training stacks for
accessible open weights. They do not update closed OpenAI/Anthropic weights locally.
[Inspect RL](https://github.com/UKGovernmentBEIS/inspect_rl) is an informative bridge
from Inspect rewards to TRL/GRPO but explicitly labels itself experimental with no
maintenance commitment. None belongs in the pilot runtime.

### Model and agent red teaming

NVIDIA [garak](https://github.com/NVIDIA/garak) is Apache-2.0 and probes leakage,
injection, jailbreak, hallucination, and other model/application risks. Use it in a
separate release-safety lane with repeated trials and calibrated detectors. It does not
evaluate repository vulnerability discovery.

[NeMo Guardrails](https://github.com/NVIDIA-NeMo/Guardrails) is Apache-2.0 and provides
programmable input/output/tool rails. It can add defense in depth but adds model calls,
latency, and failure modes. It is never the authorization boundary.

## Observability and experiment tracking

[OpenTelemetry Python](https://github.com/open-telemetry/opentelemetry-python) is
Apache-2.0 and is the recommended neutral event/span export contract. GenAI conventions
continue to evolve, so retain stable harness-owned event fields and map them at export.

For the pilot, append-only JSONL/SQLite is easier to secure and replay. Store hashes,
typed tool calls, usage, policy decisions, and redacted excerpts by default, not raw
proprietary prompts/source/secrets.

Later choices include:

- [MLflow](https://github.com/mlflow/mlflow), Apache-2.0: mature experiment,
  GenAI-tracing, evaluation, and stored-trace re-evaluation, but operationally broad.
- [Langfuse](https://github.com/langfuse/langfuse), core MIT with separately licensed
  enterprise components: strong self-hosted trace/eval UI, with additional services
  and sensitive-data custody.
- [Phoenix](https://github.com/Arize-ai/phoenix), Elastic License 2.0: technically
  capable but not OSI open source; confirm whether that meets project policy.

Any trace system needs encryption, RBAC, tenant separation, redaction, short retention
for full transcripts, and protection from prompt/tool content used as log injection.

## Deterministic scanners and evidence sources

Normalize results into the internal finding/evidence schema and SARIF 2.1 where
possible. Scanner output is a candidate claim, not ground truth.

| Tool | License/role | Harness use and caveat |
|---|---|---|
| [Semgrep CE](https://github.com/semgrep/semgrep) | LGPL-2.1 multi-language SAST engine | Strong candidate generator and SARIF source. Semgrep-maintained rules have a separate Semgrep Rules License; audit every rule pack. |
| [CodeQL queries](https://github.com/github/codeql) | MIT query repository | Excellent data-flow evidence when the organization has the required GitHub Code Security/CLI entitlement. Query license does not make the full execution stack unrestricted. |
| [Trivy](https://github.com/aquasecurity/trivy) | Apache-2.0 vuln/misconfiguration/secret/SBOM scanner | Broad preflight signal; preserve database version and evidence. |
| [Syft](https://github.com/anchore/syft) / [Grype](https://github.com/anchore/grype) | Apache-2.0 SBOM and vulnerability tools | Useful deterministic component inventory and advisory candidates. |
| [OSV-Scanner](https://github.com/google/osv-scanner) | Apache-2.0 ecosystem/SBOM scanner | Advisory and supported-language call-analysis evidence; pin database/snapshot and distinguish package presence from reachability. |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | MIT secret scanner | Run before remote context export and as a target finding source. Treat matching text as sensitive. |
| [Bandit](https://github.com/PyCQA/bandit) | Apache-2.0 Python SAST | Cheap Python baseline and false-positive corpus source. |
| [Checkov](https://github.com/bridgecrewio/checkov) | Apache-2.0 IaC scanner | Infrastructure/config evidence; deployment context remains essential. |
| [ZAP](https://github.com/zaproxy/zaproxy) / [Nuclei](https://github.com/projectdiscovery/nuclei) | Apache-2.0 / MIT dynamic scanners | Only in explicit authorized-target jobs with target/DNS/IP allowlists, rate caps, isolated networks, and strong sandboxing. Never general autonomous tools. |

Use [OpenVEX](https://github.com/openvex/spec) alongside SARIF for dependency
exploitability decisions. Keep VEX status/reason, evidence, tool/model provenance, and
human disposition. A model-generated `not_affected` assertion is not sufficient.

## Threat-modeling tools and formats

[OWASP Threat Dragon](https://github.com/OWASP/threat-dragon) is Apache-2.0 and offers
human editing for STRIDE, LINDDUN, CIA/CIA-DIE, and related approaches. It is a good
analyst UI/export target, but its formats are not interchangeable with all other threat
model tools.

[OWASP pytm](https://owasp.org/www-project-pytm/) is MIT and useful for
threat-model-as-code. Importing model-generated Python is code execution; do not make
it the agent's canonical writable format. Generate or consume it only in a sandboxed,
reviewed adapter.

The [OWASP Threat Model Library](https://owasp.org/www-project-threat-model-library/)
and CycloneDX/TM-BOM-related interchange are evolving. Keep a stable internal typed
graph of assets, actors, components, data flows, trust boundaries, assumptions,
threats, mitigations, and evidence, with adapters at the edge.

## Development toolchain

The user's proposed tools fit well:

- [mise](https://mise.jdx.dev/) pins Python and developer CLIs in a committed
  `mise.toml`. Keep secrets outside it.
- [uv](https://github.com/astral-sh/uv) manages the Python project and committed lock;
  use separate runtime/eval/dev dependency groups.
- [just](https://just.systems/man/en/) provides one discoverable set of recipes for
  setup, checks, scans, evals, gym/replay, and cost reports.
- [prek](https://prek.j178.dev/) is a Rust, pre-commit-compatible runner with `uv`
  integration. Freeze hook revisions to commit SHAs and use update cooldown/impostor
  checks.

Avoid duplicating task definitions across `mise`, `just`, CI, and Python. `mise` pins
tools, `just` names commands, and package CLIs contain business logic. CI invokes
`just` recipes.

## Defer or reject for the pilot

| Choice | Decision | Reason |
|---|---|---|
| Free-form multi-agent framework | Defer | More tokens, correlated errors, wider tool surface, and harder attribution without proven workflow gain. |
| LiteLLM proxy | Defer to Proposal 2 | Useful central gateway, unnecessary extra service for two local adapters. |
| LangGraph | Defer | Explicit state machine is easier to audit; no initial long-lived dynamic graph need. |
| Dynamic MCP/plugin installation | Reject | Unreviewed code and metadata can inherit the controller's authority. |
| Plain Docker for hostile execution | Reject | Shared host kernel; use gVisor/Kata/microVM or disable execution. |
| NeMo Gym/TRL/NeMo RL in runtime | Defer | Training-oriented, heavier, and closed model weights cannot be updated locally. |
| Model guardrails as policy | Reject | Probabilistic detection is defense in depth, not authorization or isolation. |
| Hosted traces with raw source by default | Reject | Expands proprietary code, secret, vulnerability, and retention exposure. |

## Bottom line

Build a small owned kernel and integrate the ecosystem around it. Direct adapters,
typed tools, deterministic scanners, Inspect, and a tested isolation backend cover the
initial problem without a general agent framework. The kernel's protocols make
Pydantic AI, LiteLLM, NeMo Gym, MCP, stronger sandboxes, and experiment platforms
incremental choices rather than architectural commitments.
