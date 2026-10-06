# Simplification, eval tooling and quota patch — 2026-10-05 (evening)

Branch `claude/native-transition-e2e-eval-f4ee3f`, built on `2c92d16`. Five commits:
`d162cc6` (skills), `43f8c76` (OpenShell quota patch), `5e04d27` (eval tooling),
`65fc348` (dedupe refactors), `fd4cbb7` (prompt consolidation). This records deterministic
evidence only; nothing native or live ran, because native admission capacity stayed at
1,000 of 1,000 retained claims for the whole session (read-only recheck at 21:51 UTC).

## What changed

- **Skills own the expertise.** The eight CWE skills define their oracles directly as the
  five `HARNESS_PROBE` fields with concrete positive and negative controls; the legacy
  marker protocol no runner implemented is gone. Shared safety and completion guidance lives
  once in `investigate`, which also states the verdict evidence rules. `probe` is the single
  home for the observation-line contract and correction rules. Skills: 850 → 755 lines.
- **Prompts point at skills.** The investigator instructions shrank to the contract plus
  skill pointers. The verdict retry message is now computed: it names every deficiency of
  the cited evidence (no citations, no probe cited, exit code, truncation, unverified source,
  unparsed observation line, each false prerequisite field with the `target_reached`
  meaning, polarity mismatch, contradicting probes). This removes the masking defect class
  that `c34f1cc` and `9cd4adf` corrected by hand. Admission logic is unchanged.
- **One verdict rule, one excerpt.** `definitive_support` serves both the output validator
  (tool returns) and finalization (receipts), which keep independent evidence sources.
  `Evidence.excerpt` bounds tool returns and report excerpts identically; a byte-level test
  pins the history key order. `PreparedInvestigation` carries only `deps` and still decodes
  v11 payloads. `OpenShell.download` and the qualification download step are removed (two
  fewer native admissions per `harness qualify`). The identity guard prefix derives from
  one `AGENT_NAME` constant with a test over registered activities.
- **Live evaluation is one command.** `./dev qualify`, `./dev eval` and `./dev replay`
  replace the six private helper scripts earlier sessions wrote by hand. `harness eval`
  gains `--owned-worker` (in-process worker on a fresh recorded queue that stays up until
  every owned workflow, cleanup included, is terminal), `--case` (diagnostic subset whose
  gates stay `not_checked`), `--keep-going` (continues only after terminal agent-level
  failures; every case keeps a fresh workflow ID and nothing is resent), a global
  `--settings FILE` that never merges the environment, bounded failure chains and local
  receipt summaries on failed rows, and timestamped report paths. `harness replay` replays
  a history with every native and model dispatch disabled.
- **Tracked OpenShell patch.** `deploy/openshell/patches/0001-configurable-mutation-admission-quota.patch`
  against pinned commit `6648bd0c` replaces the hard-coded 1,000-claim limit with the
  validated gateway config key `openshell.gateway.max_mutation_admissions_per_caller`
  (default 1000, range 1..=1,000,000), used for both atomic admission and the bounded expiry
  scan. Request-ID dedup, success retention, unresolved fences and caller identity are
  unchanged; a raised quota never re-admits a claimed request_id. See the patch README.

Runtime Python is 3,521 lines (from 3,351): the dedupe removed 46 lines, the eval tooling
added about 190 in `evaluation.py`, `cli.py` and `config.py`, and `retry_reasons` added 45.
The private per-session scripts it replaces are no longer needed.

## Gates

| Gate | Status | Evidence |
| --- | --- | --- |
| Deterministic suite | passed | 290 passed, 1 deselected, `HARNESS_TEST_REQUIRE_TEMPORAL=1`, Temporal CLI 1.9.1 |
| Lint, compile, API schema, generated instructions | passed | ruff, compileall, `check_api_schema.py`, `generated.py --check` |
| Preserved v11 native history replay | passed | Five completed `live-eval-v11-201cc101da4a` histories (169/175/145/103/151 events) replayed on the final code with zero native/model dispatches |
| OpenShell patch unit tests | passed | Upstream `openshell-server` lib tests 1,827 passed with Rust 1.97.1 and `bundled-z3`; `openshell-core` config 30 passed; `cargo check -p openshell-gateway` passed. Pinned Rust 1.95.0 not used for tests |
| Patched gateway artifact and deployment | not_checked | No artifact built or deployed; see the next-session plan |
| Native workspace/probe lifecycle on this candidate | not_checked | Capacity exhausted; adapter refactors (`_corroborate`, download removal) have fake coverage only |
| Live model behaviour under revised skills/prompts | not_checked | Needs a bounded diagnostic then the full cohort |
| Full 36-case cohort, success rate, unsafe negatives | not_checked | Unchanged from the previous record: last attempt failed |

No threshold, label, budget, policy or isolation setting changed. Worker identity changes
with this candidate; earlier qualification and eval reports do not apply to it.

## Build infrastructure facts established

- The pinned `rust:1.95.0-bookworm` image (digest `6258907a…d4a1`) and Debian packages are
  reachable through the qualified build-egress builder; `cmake` installs. Debian ships Z3
  only as a shared library, so the static `bundled-z3` feature from the vendored `z3-src`
  crate (Z3 5.1.0) is the offline equivalent of upstream's static Nix Z3.
- A clean clone at the pinned commit with `cargo vendor --locked` (766 crates, 1.1 GB)
  sits under the private `.harness/openshell/gateway-build/{src,vendor}` of the main
  checkout, which is the only path the managed VM can read.
- The running gateway (`/var/lib/ih-openshell/1136c19d5a/bin/openshell-gateway`, sha256
  `ac49a158…b5c4`, byte-identical to the pinned release archive) was started with a plain
  `sudo` as a session leader with `--config …/gateway-conf/gateway.toml --compute-driver docker
  --enable-mtls-auth true`, logging to `gateway.log`, its SQLite store under
  `/root/.local/state/openshell/gateway/`.
