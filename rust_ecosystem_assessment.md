# Rust Ecosystem Assessment

**Assessment date:** 2026-08-09
**Purpose:** decision support for the Rust alternative; not an approval to add a
dependency.

## Summary

Rust is a credible implementation language for a local security-harness controller.
It does not reduce the need for a hardened execution boundary. The recommended shape is
a CLI-first Rust monolith, with optional Dioxus web UI only after the core is proven.
None of the named projects should replace the harness's policy, evidence, or sandbox
contracts.

| Project | Current fit | License | Main trade-off | Recommendation |
|---|---|---|---|---|
| [Dioxus](https://github.com/DioxusLabs/dioxus) | Browser/SSR operator UI | MIT or Apache-2.0 | Adds a web server and UI dependency closure | Optional, separately built Phase 2 console. |
| [Rust/UI](https://github.com/rust-ui/ui) | Component design inspiration | MIT | Leptos/Tailwind focus; no need for a UI library in the pilot | Copy-in source only after review; no dependency. |
| [Rivet](https://github.com/rivet-dev/rivet) | Durable lifecycle/orchestration reference | Apache-2.0 | Actors, queues, WebSockets, persistence, and a service control plane add complexity | Do not adopt in the monolith. |
| [Microsoft MXC](https://github.com/microsoft/mxc) | Cross-platform sandbox-policy research | MIT | Early preview explicitly warns policies can be overly permissive | Track only; never rely on current MXC profiles as a boundary. |

## Dioxus

Dioxus supports web, SSR, desktop, and mobile with one Rust codebase and offers server
functions, middleware, WebSockets, and component primitives. That breadth is useful
only if the product has a real operator-console need. The harness should use Dioxus for
a browser UI, not a desktop client: a desktop webview brings native-system access that
does not improve a review workflow.

Use these boundaries if adopted:

- `harness-web` has its own Cargo features/lock review and only calls a read-only,
  authenticated controller API.
- The UI receives redacted report projections, not raw prompt/source/secret artifacts.
- No server function may become a generic tool, sandbox, provider, or file API.
- UI forms create approval requests; the controller verifies signed approvals and makes
  the policy decision independently.

## Rust/UI

Rust/UI is an MIT-licensed, shadcn-inspired component registry. Its stated model is to
copy components into an application rather than install a runtime component crate. This
is attractive for local ownership but does not eliminate review obligations: copied
source, CSS, icons, generated commands, and transitive frontend tooling still enter the
trusted UI supply chain.

The repository currently positions itself around Leptos and Tailwind, while the
recommended optional framework is Dioxus. Do not bridge frameworks or adopt Tailwind
solely for components. Start with Dioxus primitives and owned CSS. Reassess only when a
specific component avoids enough local work to justify its provenance and compatibility
test.

## Rivet

Rivet provides long-lived stateful actors with persistence, queues, workflows,
scheduling, WebSockets, and operational visibility. It is good inspiration for:

- explicit worker lifecycle states;
- destruction/retry/cleanup semantics;
- durable event visibility; and
- per-run ownership.

It is a poor fit for the first harness because it encourages persistent actor state,
background scheduling, and a multi-process control plane. Those are precisely the
capabilities the proposal defers until many teams need a controlled shared service.
Implement a simple `WorkerLease` and append-only event record locally instead.

## Microsoft MXC

MXC exposes a unified JSON policy and lifecycle across multiple platform sandbox
backends. Its schema/versioning and `provision -> start -> exec -> stop -> deprovision`
lifecycle are useful design references. MXC explicitly identifies itself as early preview
code and warns that some current generated policies are overly permissive; its repository
states that profiles should not currently be treated as security boundaries.

Consequently, do not include MXC in the production dependency closure. A later isolated
spike may implement an MXC `SandboxBackend` adapter for a supported developer platform,
but only after it passes the harness's own negative-reachability, network-observer,
teardown, and escape tests. The chosen OS/microVM enforcement layer remains authoritative.

## Supply-chain and build implications

Rust does not automatically create a small closure. Proc macros and `build.rs` code run
during builds; transitive native libraries, TLS choices, and frontend bundles need the
same admission review as Python packages. The Rust plan therefore requires:

- committed `Cargo.lock`, pinned Rust toolchain, reviewed registry/source policy;
- `cargo deny` for licenses/sources/advisories, `cargo audit` for advisory checks, and
  an SBOM generated from the resolved lockfile;
- no runtime `cargo install`, UI-component fetch, model/tool plugin loading, or dynamic
  code compilation;
- review of new proc macros, build scripts, native dependencies, and `unsafe` code; and
- an independent image/binary closure for sandbox backends.

## Assessment conclusion

Proceed with the small controller spike described in
[rust_implementation_plan.md](rust_implementation_plan.md). It should not include a UI,
Rivet, MXC, or Rust/UI. Dioxus is the only named project that merits a later bounded UI
experiment, and only once the CLI workflow demonstrates a shared-review requirement.
