# OpenShell gateway patches

Patches here apply on top of NVIDIA OpenShell at the pinned commit
`6648bd0c290efbc41ba131ee9831ee45cd431f94` (release v0.1.2), in filename order,
with `git apply` from the OpenShell source root.

## 0001-configurable-mutation-admission-quota.patch

Upstream hard-codes `MAX_ADMISSIONS_PER_CALLER = 1000` in
`crates/openshell-server/src/grpc/mutation_replay.rs`. Every retained claim counts toward it:
completed claims for `SUCCESS_TTL_MS` (24h), unresolved claims forever. A caller doing more
than 1000 opted-in mutations in 24h gets `RESOURCE_EXHAUSTED`. This patch makes the quota a
validated operator setting.

### Configuration

```toml
[openshell]
version = 2

[openshell.gateway]
max_mutation_admissions_per_caller = 5000
```

- Key: `max_mutation_admissions_per_caller` in the `[openshell.gateway]` table of the gateway
  TOML config file (`--config`, or the default XDG location).
- Type: `u32`. Default when the key is absent: `1000`, the same as upstream.
- Allowed range: `1..=1000000`, inclusive.
- `0` and values above `1000000` fail config load (`config_file::load` and `preflight`) with
  `invalid gateway config field 'openshell.gateway.max_mutation_admissions_per_caller': must be an
  integer between 1 and 1000000 inclusive`. Negative values, floats, strings, `nan` and `inf`
  fail as TOML parse errors, and the gateway does not start.
  `cli::prepare_server_config_with_drivers` checks the range a second time through the fallible
  `Config::with_max_mutation_admissions_per_caller`.
- There is no CLI flag or environment variable. The config-file route was feasible and follows
  the existing file-only `ssh_session_ttl_secs` pattern.
- The value is read once at startup into `openshell_core::Config::max_mutation_admissions_per_caller`,
  which is held on `ServerState::config`. It is not re-read per request.

### What changed

- `openshell-core/src/config.rs` adds:
  - `DEFAULT_MAX_MUTATION_ADMISSIONS_PER_CALLER = 1000` and
    `MAX_MUTATION_ADMISSIONS_PER_CALLER_LIMIT = 1_000_000`;
  - `validate_max_mutation_admissions_per_caller`;
  - the `Config` field, which `Config::new` sets to the default;
  - the fallible `with_max_mutation_admissions_per_caller` builder.
- `openshell-server/src/config_file.rs` adds the optional `GatewayFileSection` field and the
  range check in `parse_and_validate`.
- `openshell-server/src/cli.rs` applies the file value to `Config` at startup.
- `openshell-server/src/grpc/mutation_replay.rs` changes:
  - It removes the constant.
  - `execute_owned` reads `state.config.max_mutation_admissions_per_caller` once per call.
  - It passes that same value to the atomic
    `create_if_workspace_count_below(..., u64::from(quota))` and to
    `prune_expired(store, bucket, quota)`, which now scans `list(OBJECT_TYPE, bucket, quota, 0)`.
  - No global is used.
- `docs/how-it-works/gateways/configuration.mdx` documents the key in the example config.

### What did not change

- Request-ID validation.
- How the caller hash, bucket and admission key are derived.
- `SUCCESS_TTL_MS`.
- The `EXECUTORS` semaphore (64).
- HMAC protection, the payload hash and canonicalization.
- Proto, schema and persistence code.
- Replay and duplicate suppression:
  - A completed claim still replays with `openshell-replayed: true`.
  - An unresolved claim still never expires and still returns `REQUEST_OUTCOME_UNCERTAIN`.
  - A changed payload still returns `REQUEST_ID_PAYLOAD_MISMATCH`.
  - Deduplication by `get_by_name` and the unique key happens before the quota check, so
    raising the quota cannot admit an already-claimed `request_id` again.

### Tests added or adapted

- `mutation_replay/tests.rs`:
  - `state_for` now delegates to a new `state_with_quota(store, quota)` and keeps the default.
  - Adapted: `quota_fails_closed_but_replays_and_expired_success_cleanup_still_work` now reads
    the quota from state and asserts that the default is 1000. The existing `prune_expired`
    call now passes the state quota.
  - New: `configured_quota_admits_beyond_default_and_refuses_at_configured_limit` sets the quota
    to 1003. Admission succeeds at count 1000 and is refused at 1003, no side effect happens
    when it is refused, and a replay still works while the bucket is full.
  - New: `raising_quota_never_readmits_claimed_request_ids` starts with a file-backed SQLite
    store and quota 3, holding one completed claim, one unresolved claim and one more completed
    claim, so a fourth request is refused. After a restart with quota 10:
    - both completed claims replay;
    - the unresolved claim stays `REQUEST_OUTCOME_UNCERTAIN` and the handler call count is
      still 1;
    - a payload mismatch is still rejected and the workspace count is unchanged;
    - only the previously refused new request is admitted.
  - New: `pruning_scan_uses_configured_quota_and_keeps_unresolved_claims`. A scan bounded at
    quota-1 does not reach the expired row, while a scan at the quota removes it. Unresolved
    claims survive a 1,000,000-row scan.
- `config_file.rs`:
  - `mutation_admission_quota_is_optional_and_parsed` covers an absent key and the values 1,
    5000 and 1000000.
  - `rejects_out_of_range_mutation_admission_quota` checks that 0, 1000001 and 4294967295
    return `InvalidValue`, and that -1, 4294967296, 1.5, "5000", nan and inf return `Parse`.
- `cli.rs`: `server_config_preparation_reads_mutation_admission_quota_once` checks that
  preparing the startup config gives 1000 with no key, 5000 when set, and a startup error for
  0 and 1000001.
- `openshell-core config.rs`: `mutation_admission_quota_defaults_and_validates`.

### Verification run (macOS arm64, Rust 1.97.1, `--offline`)

All commands ran from the OpenShell source root with `RUSTUP_TOOLCHAIN=1.97.1`.

| Command | Result |
| --- | --- |
| `cargo test -p openshell-server --features bundled-z3 --lib grpc::mutation_replay` | `test result: ok. 44 passed; 0 failed; 1 ignored` |
| `cargo test -p openshell-server --features bundled-z3 --lib config_file` | `test result: ok. 44 passed; 0 failed; 0 ignored` |
| `cargo test -p openshell-server --features bundled-z3 --lib cli::` | `test result: ok. 77 passed; 0 failed; 0 ignored` |
| `cargo test -p openshell-core --lib config::` | `test result: ok. 30 passed; 0 failed; 0 ignored` |
| `cargo test -p openshell-server --features bundled-z3 --lib` (full crate) | `test result: ok. 1827 passed; 0 failed; 8 ignored` |
| Final rerun after a doc-comment-only lint fix: `cargo test ... --lib -- grpc::mutation_replay config_file cli::` | `test result: ok. 165 passed; 0 failed; 1 ignored` |
| `cargo check -p openshell-gateway` | passed (exit 0) |
| `cargo clippy -p openshell-core -p openshell-server --features openshell-server/bundled-z3 --all-targets` | exit 0. The one patch-introduced warning (`doc_link_code`) was fixed and a clean core clippy rerun confirmed it. One pre-existing warning remains in untouched `grpc/policy.rs`. |
| `cargo fmt -p openshell-server -p openshell-gateway -p openshell-core -- --check` | clean |
| `git apply --check` against pristine pinned files, and `git apply --check --reverse` against the working tree | both pass |

### Limitations

- Tests ran with Rust 1.97.1, not the pinned 1.95.0, which is not installed here. They have not
  been run with 1.95.0.
- The ignored mutation_replay test is the existing Postgres test. It needs
  `OPENSHELL_REPLAY_TEST_DATABASE_URL`, so it was not run, and Postgres was not exercised. The
  other 7 ignored tests in the full run are pre-existing and also not run.
- Linking `openshell-server` test binaries needs `libz3`. There is no system z3 here, so tests
  used the crate's own `bundled-z3` feature, which builds z3 from the already-vendored
  `z3-src` crate and is the same feature upstream CI uses for the gateway. The reproducible
  gateway build needs `bundled-z3` or a system z3 as before; this patch does not change that.
- If the quota is lowered below a caller's current retained-claim count, new admissions for that
  caller are refused until enough completed claims pass the 24h TTL. Pruning scans only the
  oldest `quota` rows (`ORDER BY created_at_ms, name`), so after lowering the quota, expired rows
  beyond that window are removed only after older rows are. Unresolved claims still need
  reconciliation, as upstream.
- `Cargo.lock` is unchanged. The patch contains no binary files.
