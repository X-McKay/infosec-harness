# Security Agent Harness Research

**Research cutoff:** 2026-08-09
**Scope:** authorized source-code vulnerability discovery, security review, threat
modeling, and false-positive triage with closed and open model providers.

## Executive decision

Start with **[Proposal 1: bounded evidence pipeline](proposals/01-bounded-evidence-pipeline.md)**.
It is the simplest design that preserves the controls that matter: a small provider
interface, typed artifacts, deterministic stage transitions, hard budgets, an
ephemeral offline sandbox, and human review of consequential conclusions. Do not
start with a free-form multi-agent swarm or online reinforcement learning.

The key design choice is to make the LLM an investigator inside a conventional
security pipeline, not the security boundary or the final authority. Static analysis,
scope checks, sandbox isolation, budget enforcement, evidence validation, and release
gates remain deterministic code. The model proposes searches, explanations, tests,
and dispositions; the harness decides what can run and what may leave the system.

After a pilot demonstrates value on an internal held-out set, adopt the queue,
central policy, and shared sandbox pool from
**[Proposal 2: controlled service](proposals/02-controlled-service.md)**. Build
**[Proposal 3: security research platform](proposals/03-security-research-platform.md)**
only when continuous benchmark work, local-model training, or many isolated
concurrent workers justify the operational burden.

## What the evidence supports

1. **Measure systems, not model names.** Agent scaffold, prompt, tool set, context,
   retry policy, and budget can materially change results. Vendor benchmarks are
   useful capability signals, not performance forecasts for this harness.
2. **Require executable or inspectable evidence.** Recent real-world vulnerability
   benchmarks remain substantially harder than classification and knowledge tests.
   A persuasive narrative is not a validated finding.
3. **Use a cascade.** Run deterministic scanners and deduplication first, a low-cost
   model for routine structured triage, and a stronger model only for ambiguous or
   high-impact cases. Reserve independent verification for the cases where it changes
   a decision.
4. **Treat all target content as hostile.** Source, comments, documentation, issue
   text, build output, dependencies, and tool results may contain prompt injection or
   exploit the analysis environment. Instructions in those channels have no authority.
5. **Keep evaluation independent.** UK AISI's Inspect is the strongest current
   Python-native, provider-neutral base for reproducible agent evaluations and
   sandboxed cyber tasks. OpenAI's hosted Evals platform is scheduled to become
   read-only on 2026-10-31 and shut down on 2026-11-30, so it should not be the
   harness's evaluation foundation.
6. **Improve offline before training online.** Use human-reviewed trajectories to
   improve prompts, tools, routing, and retrieval first. Closed models usually leave
   the controller as the trainable policy. Keep public and internal test sets strictly
   held out from any reward or prompt-optimization loop.
7. **Model the deployed system, not only its repository.** Assemble a versioned,
   provenance-aware context bundle from catalogs, runtime inventory, IAM, API/data
   metadata, telemetry, and owner-reviewed business invariants. Preserve conflicts
   and missing coverage instead of asking a model to choose a convenient truth.
8. **Validate in a production-free range.** A failed reproduction is not a false
   positive. Active issue validation uses an immutable plan, synthetic identities and
   data, deterministic out-of-band oracles, and a two-sided sandbox that isolates both
   target code and internal systems.
9. **Treat shared infrastructure as an attack path.** Evaluation guests receive a
   signed dependency closure and cannot reach package registries, caches, artifact
   stores, CI helpers, answer stores, or general egress services.
10. **Optimize for landed remediation.** Findings create risk reduction only after a
    tested patch, owner review, and verified deployed fix; record that lifecycle in
    addition to finding quality and cost.

## Proposed common stack

| Concern | Initial choice | Reason |
|---|---|---|
| Language | Python 3.12, pinned by `mise` | Mature SDK, typing, security, and eval ecosystem |
| Packages | `uv` with a committed lockfile | Fast, reproducible dependency resolution |
| Commands | `justfile` | One discoverable interface for local and CI tasks |
| Hooks | `prek`, revisions frozen to commit SHAs | Fast pre-commit compatibility and supply-chain safeguards |
| Schemas | Pydantic models plus JSON Schema | Provider-independent, validated artifacts |
| Providers | Thin native OpenAI/Anthropic adapters behind a local protocol | Preserves provider-specific capabilities and minimizes hidden behavior |
| Runtime | Explicit state machine, not a general graph framework | Easier policy review, replay, and cost attribution |
| Sandbox | Rootless OCI for non-executing review; gVisor/Kata/microVM for target code | No silent fallback from a required stronger boundary |
| Findings | SQLite metadata plus content-addressed local artifacts | Simple transactions, provenance, and replay |
| Evaluation | Inspect AI and selected `inspect_evals` cyber tasks | Provider-neutral solvers, scorers, logs, approvals, and sandboxes |
| Gym API | A typed environment core with a Gymnasium-compatible wrapper | Reuses production tools without coupling production to RL |
| Telemetry | Redacted OpenTelemetry-compatible events and local JSONL first | Portable traces without exporting sensitive prompts by default |

`LiteLLM` is a reasonable optional gateway in Proposal 2 when centralized keys,
budgets, and routing are needed. It should not define the harness's domain model, and
the pilot does not need another network service. `Pydantic AI`, LangGraph, OpenHands,
and similar frameworks are useful references or optional integrations, but none is a
substitute for the authorization, evidence, and sandbox layers.

## Deliverables

- [Literature review](literature-review.md): OpenAI, Anthropic, NVIDIA, and
  cross-vendor research, with claims separated from limitations.
- [Open-source landscape](open-source-landscape.md): framework, evaluation,
  sandbox, observability, and security-tool choices.
- [GitHub trending follow-up](trending-github-scan-2026-08-09.md): recent relevant
  projects, bounded spikes, and explicit non-adoption decisions.
- [Reference architecture](reference-architecture.md): shared domain model,
  workflows, trust boundaries, provider API, and cost controls.
- [External context and safe issue validation](context-and-safe-validation.md):
  provenance-aware system context, secure connectors, validation plans, escalation
  ladder, lab topology, and false-positive semantics.
- [Evaluation and gym](evaluation-and-gym.md): test pyramid, benchmark portfolio,
  metrics, environment contract, reward design, and improvement loop.
- [Implementation plan](implementation-plan.md): delivery increments, telemetry and
  cost ledger, value metrics, evaluation/testing cadence, and promotion gates.
- [Proposal 1](proposals/01-bounded-evidence-pipeline.md): single-operator pilot.
- [Proposal 2](proposals/02-controlled-service.md): multi-team controlled service.
- [Proposal 3](proposals/03-security-research-platform.md): distributed evaluation
  and training platform.

## Decision gates

Advance beyond Proposal 1 only when all of the following are measured on a held-out,
representative internal corpus:

- The harness improves validated findings per analyst-hour over the existing workflow.
- High-severity false-dismissal rate stays within an AppSec-approved bound.
- Every confirmed finding carries evidence that another person can reproduce.
- Cost and latency are predictable at the repository and finding level.
- Prompt-injection, egress, secret-access, and runaway-budget tests pass.
- Context provenance, freshness, conflicts, validation environment fidelity, and
  non-reproduction outcomes pass dedicated tests.
- At least one OpenAI and one Anthropic adapter pass the same contract suite.

No public benchmark score replaces these gates.

## Proposal comparison

| Dimension | Proposal 1: bounded pipeline | Proposal 2: controlled service | Proposal 3: research platform |
|---|---|---|---|
| Primary user | One analyst or small AppSec team | Multiple internal teams | Dedicated security/eval researchers |
| Runtime | Local CLI, one controller | API, durable jobs, shared workers | Distributed experiments plus separate training zone |
| State | SQLite + local artifacts | PostgreSQL + encrypted object storage | Dataset/trajectory/eval registries and experiment lineage |
| Isolation | No-exec rootless OCI; gVisor/Kata/microVM for target code | Worker pools by trust class; stronger proof workers | Dedicated accounts/nodes and microVM-class episode isolation |
| Provider control | Native adapters and local budgets | Central broker/gateway, identity, quotas | Separate production/eval/training credentials and promotion bundles |
| Evaluation | Inspect + private pilot set | Central registry, shadow/canary releases | Large campaigns, private temporal suites, reward-hacking controls |
| RL path | Record/replay and controller experiments | Organization-wide offline routing/policy data | Optional SFT/preferences/RL for approved open weights |
| Incremental scope | Roughly 6-10 engineer-weeks for a complete pilot | Roughly 12-20 engineer-weeks after Proposal 1 | Roughly 30-50 engineer-weeks after Proposal 2, before optional training |
| Choose when | Proving security value and unit economics | Governance, durability, and multi-team scale are measured needs | At least two funded research/training/high-risk-range objectives exist |

The ranges are planning aids for experienced teams, not commitments; corpus creation,
enterprise integrations, compliance, and high-assurance host operations can dominate
them.

## Source convention

This review favors vendor technical publications, peer-reviewed papers, official
documentation, and maintained source repositories. Vendor-reported benchmark results
are labeled as vendor evidence. Repository activity and product behavior are snapshots
at the research cutoff and should be rechecked before implementation. Model prices,
IDs, retention terms, and access controls change too quickly to hard-code from this
document; store dated configuration and reconcile against actual provider usage.
