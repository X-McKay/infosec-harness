# Rust Alternative Implementation Plan

## Scope and constraints

This plan implements the Rust alternative from [rust_proposal.md](rust_proposal.md).
It deliberately shares the baseline's safety model and acceptance gates. The goal is
not a new product architecture; it is a small, maintainable Rust implementation of the
same bounded evidence pipeline.

The first release is a single-user CLI on a supported Linux development/CI host. The
controller is a local process. Sandboxed work is disposable and offline. A UI, shared
service, background queue, remote database, long-lived agents, and generic plugin
system are out of scope.

## Engineering rules

- One workspace; one production crate/binary; no internal crate split until a compiler
  boundary, independent release, or optional UI proves necessary.
- Domain and policy functions are deterministic, synchronous, and side-effect free.
  I/O adapters translate inputs to domain types and return typed results.
- Keep `async` in `main`, provider, process, and file/network adapter layers. Do not
  spread it through policy and evaluation code.
- All external input is deserialized to an owned schema before use. Unknown fields,
  schema-version mismatch, signature failure, and invalid paths fail closed.
- Shell commands are catalogued argv templates, never model-authored strings. The
  model cannot select a binary, destination, environment variable, mount, or network
  policy.
- `Cargo.lock` is committed. CI rejects dependency/source/license changes without a
  reviewed admission record and an SBOM update.

## Repository shape

```text
Cargo.toml                 # workspace and dependency policy
crates/harness/
  src/
    main.rs                # CLI wiring only
    lib.rs                 # public module boundary
    domain.rs              # manifests, findings, evidence, reports
    policy.rs              # pure allow/deny and budget decisions
    workflow.rs            # explicit state transitions
    providers.rs           # OpenAI, Anthropic, fake, replay adapters
    executor.rs            # sandbox and approved tool protocol
    store.rs               # SQLite and artifact references
    telemetry.rs           # redacted JSONL/tracing events
  tests/                   # contract, fixture, adversarial tests
policies/                  # signed examples and approved tool catalog
fixtures/                  # SARIF, source snapshots, model responses
docs/                      # schema and operational notes
```

Keep implementation modules private by default. Expose a small public library API only
if an optional Dioxus UI or external evaluator later needs it.

## Delivery increments

### R0: reproducible toolchain and supply-chain controls

Build:

- `mise.toml` pinning Rust stable and supported auxiliary tools.
- `Cargo.toml`, committed `Cargo.lock`, `justfile`, `prek`, rustfmt, Clippy, and CI.
- `cargo fmt --check`, `cargo clippy -- -D warnings`, tests, `cargo deny`, `cargo audit`,
  SBOM generation, secret scan, and dependency-diff policy.
- A minimal dependency set: `serde`, `serde_json`, `schemars`, `clap`, `thiserror`,
  `tokio`, `reqwest`, `rusqlite`, `tracing`, and test-only libraries. Every addition
  uses the existing integration-admission process.

Exit: a clean machine builds a locked binary; CI rejects unlocked or unreviewed
dependency changes. No runtime crate/plugin/tool install path exists.

### R1: pure trusted core

Build:

- Versioned Rust structs/enums for authorization, task, budget, finding, evidence,
  disposition, `EgressPolicy`, `NetworkEvidence`, run state, and report.
- JSON Schema emission and fixture compatibility checks.
- A table-driven finite state machine:
  `ingested -> preflight -> collecting -> assessing -> verifying -> review_required -> complete`.
- Pure policy functions for signatures, expiry, paths, tool catalog, budgets, data class,
  and egress decisions.
- SQLite migrations and content-addressed artifact naming. Store hashes and references
  separately from sensitive body data.

Tests:

- property tests for state-transition validity, budget monotonicity, canonical-path
  containment, and egress default denial;
- golden fixtures for report and schema compatibility; and
- malformed/unknown schema, expired manifest, symlink, and signature-negative cases.

Exit: policy and workflow tests run without network, provider access, or sandbox.

### R2: bounded read-only workflow

Build:

- SARIF importer preserving rule, location, code flow, fingerprint, revision,
  suppression, and coverage data.
- Typed `read`, `search`, and `tree` tools with byte/result/time quotas.
- Sandbox executor contract with a rootless, network-disabled read-only worker;
  explicit result, timeout, and teardown records.
- Fake and replay `ModelBackend` adapters. The provider trait accepts a normalized
  request and returns structured output, usage, request identity, and classified error.
- Controller-managed OpenAI and Anthropic REST adapters using reviewed schemas. Record
  request metadata and usage without hidden reasoning or raw secret material.
- Evidence-backed report generation and human disposition export.

Required commands:

```text
just check
just test
just policy-self-test
just sandbox-self-test
just network-self-test
just triage SARIF TARGET REVISION
```

Exit: fake/replay, malformed model output, provider refusal, tool denial, and timeout
are distinct terminal states. Workers cannot initiate a network connection or access
host credentials, engine sockets, or unapproved files.

### R3: network evidence, telemetry, and cost

Build:

- Signed per-run `EgressPolicy` compiler. The ordinary worker uses no network; any
  exceptional edge is a narrow, expiring allowance.
- A `SandboxBackend` adapter that applies policy outside the process and an independent
  collector for DNS/connect attempts, destination resolution, bytes, verdicts, and
  collector health.
- Automatic containment: deny -> terminate worker -> revoke lease -> quarantine
  artifacts -> persist a `network_contained` event -> notify the named owner.
- Redacted JSONL events and SQLite summaries for run, dependency, stage, provider,
  tool, network, finding, safety, and remediation events.
- A dated provider-cost catalog, preflight reservations, actual-usage reconciliation,
  and per-run report.

Tests:

- allowed local synthetic path; denied IPv4/IPv6, DNS, metadata, registry, CI,
  artifact/cache, host bridge, proxy tunnel, direct provider, and observer-failure
  cases;
- containment timing and artifact quarantine; and
- telemetry redaction, retention, and no-unmatched-flow checks.

Exit: network observer coverage is 100%; unexpected or unobserved egress is zero; an
observer failure prevents the run from becoming actionable.

### R4: evaluation and Rust/Python decision gate

Build:

- A local task-manifest registry, fake provider fixtures, owned regression cases, and
  private corpus adapter. Keep Inspect as an external evaluator or invoke it through a
  serialized manifest rather than embedding Python into the trusted Rust core.
- Comparable repeated-run metrics: precision, false-dismissal, evidence validity,
  analyst time, cost, latency, policy violations, and containment outcomes.
- Replay of the same fixture corpus through the Rust and baseline implementations.

Exit: Rust meets the baseline's safety and quality gates with no material increase in
dependency closure, operator workload, or cost. Otherwise close the alternative and
retain the baseline language.

### R5: optional web-console spike

Only after R4 and a demonstrated multi-reviewer requirement:

- Add `harness-web` using Dioxus web/SSR, with a separate build and dependency lock.
- Expose an authenticated, read-only report API with paging and server-side filtering.
- Show run state, evidence references, budgets, network containment, and approval
  requests. Never stream raw prompts, secrets, target output, or sandbox shell access.
- Keep policy evaluation and provider/sandbox credentials in `harness`; the UI cannot
  write manifests or dispatch tools.
- Start with owned CSS/Dioxus primitives. Evaluate one Rust/UI copy-in component only
  after an explicit Dioxus-compatibility and provenance test.

Exit: the UI adds measurable review-time value without changing the controller's threat
model or granting new authority.

## Project-specific follow-up

| Candidate | Spike question | Admission decision |
|---|---|---|
| Dioxus | Can an isolated, read-only SSR console improve review time? | Optional R5 only; MIT/Apache-2.0 review and separate dependency closure. |
| Rust/UI | Does one copied component work cleanly with the selected Dioxus version? | No framework adoption; only locally owned, reviewed source if needed. |
| Rivet | Do durable actors solve a measured multi-user scheduling problem? | Defer until a controlled-service phase; do not add to CLI monolith. |
| MXC | Can a platform-specific backend pass all containment tests? | Research adapter only. MXC's current preview policy must not be trusted as a boundary. |

## Rust-specific review checklist

- `unsafe` is forbidden in harness-owned code by workspace lint; any exception has a
  written rationale, isolation analysis, tests, and owner.
- `cargo deny` checks licenses, advisories, bans, and source provenance; review its
  configuration rather than accepting defaults.
- Block `build.rs` and proc-macro additions unless an admission review demonstrates
  value. They execute during builds and belong in the supply-chain threat model.
- Pin container images and tool binaries separately from Cargo dependencies.
- Fuzz parsers and policy boundaries with `cargo fuzz` or an equivalent isolated CI job;
  do not fuzz against real providers or external targets.
- Test JSON deserialization limits, recursive data, archive/file handling, command argv,
  symlink resolution, signing, and redaction as security boundaries.

## Decision record

At R4, publish a short decision record with:

1. Held-out quality and safety results relative to the baseline.
2. Dependency count, licenses, advisories, build complexity, and patching burden.
3. Operator/developer onboarding time and incident response ergonomics.
4. Measured binary/startup/memory characteristics only where they affect an actual
   operating constraint.
5. Explicit recommendation: adopt Rust controller, retain baseline, or use Rust only
   for a separately justified helper.
