# Rust Alternative Proposal

## Decision framing

This document describes a Rust implementation path for the security-agent harness. It
is an alternative to the Python proposal, not a commitment to rewrite. It preserves the
same non-negotiable controls: a bounded evidence workflow, deterministic policy,
controller-mediated model calls, offline workers by default, independent network
enforcement, immutable evidence, and human review of consequential outcomes.

**Recommendation:** approve a short Rust feasibility spike before selecting a runtime.
Choose Rust for the controller only if the team can demonstrate equal provider
correctness and a materially better operational profile. Do not select it because a
frontend is appealing, and do not begin with a web service.

## What We Would Build

One local Rust application with a CLI-first workflow:

```text
signed manifest -> preflight -> deterministic evidence collection
                -> model assessment -> independent verification -> report
```

The application owns:

- typed domain records for authorization, evidence, findings, policy, budgets, network
  events, and reports;
- a finite state machine with explicit terminal states;
- direct HTTP adapters for approved OpenAI and Anthropic APIs;
- a narrow, subprocess-based sandbox/executor contract;
- SQLite, content-addressed artifacts, and append-only JSONL telemetry;
- deterministic policy and network-evidence validation; and
- a CLI for triage, replay, report generation, self-tests, and evaluation.

The application does **not** initially own a queue, plugin marketplace, MCP runtime,
agent graph, distributed worker pool, vector store, general model gateway, or web UI.

## Why Rust Could Be Worth It

Rust can reduce controller failure modes around memory safety, concurrent state, and
resource handling. Its single static binary is convenient for a locally operated
security tool, and its strong type system fits immutable manifests and explicit state
transitions. Cargo lockfiles, crate-level licensing checks, and small binary deployments
also align with a minimized trusted base.

Rust does not make target-code execution, provider access, prompt injection, egress,
or dependency compromise safe. The isolation boundary remains the OS/microVM and the
policy remains deterministic code. A Rust rewrite is not justified if it slows down
provider integration, evaluation work, or security review without a clear benefit.

## Minimal Architecture

Keep one Cargo workspace with a single production binary and library, and add a separate
optional UI crate only when a web console is approved.

```text
crates/
  harness/                 # library plus CLI binary; production trusted core
    domain/                # serde types and stable artifact schemas
    policy/                # pure manifest, budget, path, and egress decisions
    workflow/              # explicit state machine and stage orchestration
    providers/             # thin approved-provider HTTP adapters
    executor/              # sandbox process protocol and result normalization
    store/                 # SQLite, artifact hashes, JSONL audit
    telemetry/             # redacted events and summaries
  harness-web/             # optional Dioxus operator console, no policy authority
```

`harness` is the only default build target. It should compile and operate without a UI,
network service, or external database. Keep domain and policy code synchronous and pure;
use Tokio only at I/O boundaries. No business decision is encoded in a template, shell
script, or model prompt.

## Initial Technology Choices

| Concern | Start with | Rationale |
|---|---|---|
| Runtime/toolchain | Rust stable pinned with `mise`; Cargo; `just`; `prek` | Conventional Rust build and reproducible developer workflow. |
| Domain schemas | `serde`, `serde_json`, `schemars` | Typed artifacts plus reviewable JSON Schema without a framework. |
| CLI/errors | `clap`, `thiserror` | Standard command and error boundaries. |
| Async/I/O | `tokio`, `reqwest` | Mature HTTP/process I/O; confine them to adapters. |
| Storage | SQLite through `rusqlite`, plus local content-addressed files | One process, simple backup and audit story. |
| Telemetry | `tracing` and local JSONL, OpenTelemetry export later | Structured diagnostics without a required telemetry service. |
| Validation | `cargo test`, `proptest`, `insta`, fixture tests | Unit/property/golden coverage for policy and reports. |
| Supply-chain checks | `cargo deny`, `cargo audit`, reviewed `Cargo.lock` | License, advisory, and source controls in CI. |

Each crate needs an owner, license review, pinned version, SBOM entry, and admission
test. Prefer direct REST adapters over unofficial provider SDKs if doing so avoids a
large transitive closure; the API contract suite then becomes the portability boundary.

## Frontend Position

The initial product remains CLI plus generated Markdown/JSON reports. A web console is
useful only after multiple reviewers need shared, concurrent visibility into runs,
evidence, budgets, and containment events. It must be read-only for the pilot: it may
display state and create a reviewed approval request, but it cannot issue tools, amend
manifests, stream prompts, or bypass policy.

If a console is approved, use a separate Rust `harness-web` crate with
[Dioxus](https://github.com/DioxusLabs/dioxus) for a browser-based operator interface.
Dioxus is mature enough for a bounded UI experiment, supports web/SSR and is dual
MIT/Apache-2.0. Keep the UI server separate from the controller process or expose only a
small, authenticated read API. Do not ship desktop/webview builds: their native system
access is unnecessary and expands the trust boundary.

Do not make [`rust-ui/ui`](https://github.com/rust-ui/ui) a production dependency. It is
MIT licensed and its copy-in component model limits runtime dependency risk, but it is
currently designed for Leptos and Tailwind rather than Dioxus. Borrow a component only
after a license/provenance review and local ownership; otherwise use Dioxus primitives
and small owned CSS.

## Named Project Assessment

| Project | Value | Decision for the alternative | Reason |
|---|---|---|---|
| [Dioxus](https://github.com/DioxusLabs/dioxus) | Rust web/SSR UI and type-safe components | Optional Phase 2 UI spike | Mature project and permissive dual license; still unnecessary for CLI-first pilot. |
| [Rust/UI](https://github.com/rust-ui/ui) | Copy-in component patterns and restrained UI inspiration | Inspiration only | Leptos/Tailwind orientation and generated component code need review; do not introduce it as a framework. |
| [Rivet](https://github.com/rivet-dev/rivet) | Durable actor lifecycle, cleanup, event visibility | Architecture reference only | Its persistent actors, queues, scheduling, WebSockets, and service footprint conflict with the local-monolith and short-lived-worker goals. Reconsider only for a later shared service. |
| [Microsoft MXC](https://github.com/microsoft/mxc) | Unified cross-platform sandbox schema and lifecycle ideas | Track; do not trust or depend on it | MXC is an early preview and explicitly warns current policies can be overly permissive. It is not a security boundary for this harness. |

Rivet's useful lesson is to make every worker lifecycle observable and destructible.
Implement that as a small `Run`/`WorkerLease` state machine, not as long-lived agent
actors. MXC's useful lesson is a versioned, backend-independent execution policy. Keep
the harness's `SandboxBackend` and signed `EgressPolicy`, but use a selected mature OS
or microVM boundary underneath.

## Non-Negotiable Security Shape

- The controller makes provider requests; ordinary workers have no NIC.
- A worker gets a signed, expiring `EgressPolicy` only when an approved task requires a
  synthetic target or narrow broker path.
- Network policy enforcement and evidence collection run outside the worker.
- SQLite and artifacts are local to the controller; workers receive only task-scoped
  copies and cannot reach controller, graders, registries, caches, CI, or metadata.
- The UI never has sandbox, provider-key, or policy-write authority.
- No `unsafe` code in the trusted core without an explicit design review, safety proof,
  focused tests, and a named owner. Prefer no `unsafe` in the application workspace.

## Go/No-Go Spike

Timebox a two-week spike using one read-only SARIF triage workflow. It must implement:

1. Signed manifest parsing and pure policy decisions.
2. Fake/replay plus one live provider adapter with typed JSON output and usage accounting.
3. Read-only tool execution, network-disabled worker, and a `network-self-test`.
4. SQLite/JSONL audit, content-addressed evidence, and deterministic report output.
5. Equivalent contract, malformed-output, policy, and replay tests to the Python plan.

Choose Rust only if the spike passes all safety tests, is operable by the expected team,
and does not increase the dependency closure or delivery estimate materially. Otherwise
retain Python for the controller and consider Rust only for a narrowly justified helper.

## Outstanding Decisions

1. Is there a team-maintenance advantage for Rust that outweighs Python's faster
   security/LLM evaluation ecosystem?
2. Can direct, minimal REST adapters meet the approved OpenAI and Anthropic feature
   contracts without pulling in a large SDK graph?
3. Which Linux/macOS/Windows operating environments are actually in scope? Cross-platform
   controller support must not imply cross-platform active validation.
4. Does Phase 2 have a demonstrated multi-user review need that warrants a web console?
5. Does the Rust spike meet the same cost, safety, and evaluation gates as the baseline?
