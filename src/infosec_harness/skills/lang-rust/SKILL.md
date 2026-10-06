---
name: lang-rust
description: 'Conventions for Rust repositories: Cargo workspaces, offline builds, example-binary probes
  and unsafe code. Use this when the repository is primarily Rust; the workspace image has no Rust toolchain by default.'
metadata:
  owner: appsec
  version: 1.0.0
---

# Rust repositories

## First: check the toolchain

The workspace image does **not** include Rust. Before anything else run
`command -v cargo rustc` and, if both print paths, `cargo --version`. If either is absent,
read the code to locate the sink and guard, then follow "When the toolchain is absent".

## Use this skill when

- The repository has a `Cargo.toml` or the finding's sink is in a `.rs` file.

## Do not use this skill when

- The crate is a vendored dependency no production entry point calls.
- You are planning installs — use `environment`. This skill grants no permissions.

## Recognize the project

- **Manifests:** `Cargo.toml` (`[package]`, `[workspace] members`, `[lib]`, `[[bin]]`,
  `[features]`, `[profile.*] panic`), `Cargo.lock`, `rust-toolchain`/`rust-toolchain.toml`,
  `.cargo/config.toml` (source replacement, vendoring), `build.rs` (runs at build time).
- **Layout:** `src/lib.rs` (library API), `src/main.rs` or `src/bin/*.rs` (binaries),
  `tests/` (integration tests), `examples/`, `benches/`.
- **Entry points:** actix/axum/rocket/warp handlers, `fn main`, public library functions,
  `#[no_mangle] extern "C"` functions called from other languages.
- **Sinks to note:** `unsafe` blocks (raw pointers, `get_unchecked`, `from_raw_parts`,
  `transmute`), `Command::new("sh").arg("-c")`, `format!` into SQL passed to `query`/`execute`,
  `Path::join` with an absolute untrusted segment (replaces the base), `serde` into
  attacker-chosen types, indexing that panics (denial of service, not memory corruption).

## Inspect dependencies offline

Read `Cargo.lock` for exact versions and `[patch]`/`[replace]` overrides. With a toolchain,
`cargo metadata --frozen --format-version 1` and `cargo tree --frozen` work offline once
sources are present: a committed `vendor/` with `.cargo/config.toml` source replacement, or a
registry cache under the `CARGO_HOME` below, populated once in the workspace with
`cargo fetch --locked` (it fetches only what `Cargo.lock` pins). A policy denial of that fetch
is a limitation, not a reason to try another source.

## Compile and run a probe

Cargo hard-links build outputs, and the archive check rejects hard links: never leave a
`target/` directory under `/workspace/repo`. Build inside `run_probe`, with the target dir in
`/tmp` and every flag offline:

```bash
export CARGO_HOME=/workspace/repo/.harness-deps/cargo CARGO_TARGET_DIR=/tmp/harness-target \
  CARGO_NET_OFFLINE=true
cargo build --frozen --example harness_probe && /tmp/harness-target/debug/examples/harness_probe
```

- A probe in `examples/harness_probe.rs` sees only the crate's `pub` API. Private items are
  not reachable without editing source, which is forbidden: drive the nearest public entry
  point instead.
- A binary-only crate: build the binary and drive it with argv/stdin from a Python or shell
  probe that prints the line.
- `rust-toolchain.toml` pins may trigger a rustup download; a pinned version that is not
  installed is a limitation, not something to fetch.
- Catch panics around the target call with `std::panic::catch_unwind` (unless the profile sets
  `panic = "abort"`) so the line still prints; a panic is itself an observation.

## Memory-safety observation

Safe Rust bounds-checks and panics; memory corruption needs `unsafe`. AddressSanitizer and
Miri need a nightly toolchain that is not available: use a guard-page buffer or an observable
invariant (a canary value the probe placed next to the target buffer), with a positive control.

## The HARNESS_PROBE line

`bool` formats as `true`/`false`, so no JSON crate is needed:

```rust
println!("HARNESS_PROBE {{\"target_reached\":{},\"oracle_valid\":{},\"positive_control\":{},\"negative_control\":{},\"vulnerability_observed\":{}}}", t, o, p, n, v);
```

`cargo test` prints a `test result:` summary after your output, which breaks the last-line
rule: use an example binary, not a test harness, for the evidence-bearing run.

## Common failure modes

- `--frozen` failing on a missing `Cargo.lock` entry or crate source: dependency limitation.
- Feature-gated code (`#[cfg(feature = "...")]`) not compiled: pass `--features` explicitly.
- `build.rs` compiling C through the `cc` crate needs `gcc`; it may also need headers.
- An incremental cache from the workspace masking a change: the `/tmp` target dir avoids it.

## When the toolchain is absent

Run `command -v cargo rustc` first. If either prints nothing, Rust is not installed in this
image: do not download rustup, a toolchain archive or crates, and do not rewrite the crate in
another language (a rewrite is a stand-in). Return `inconclusive`, name the missing tool
(`cargo: not found`) as the limitation in the verdict summary, and record what reading
established. A `rust-toolchain.toml` or CI file naming Rust is not execution evidence.

## Completion criteria

- You can name the crate, the public entry point that reaches the sink, and either the probe
  binary you ran or the exact missing tool.
