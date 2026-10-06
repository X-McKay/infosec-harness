# Operator and development utilities

- `dev_setup.py`: pinned checkout-local tools, the Linux VM that builds trusted images and hosts
  native OpenShell, the generated `dev.env`, and `ready`, the bounded GET-only API, Temporal and
  UI readiness check behind `./dev smoke`. From a git worktree it uses the main checkout's
  `.harness/`.
- `openshell_artifacts.py`: checksum-verified native release downloads.
- `openshell_guest.py`: dedicated OpenShell daemon with explicit ownership and firewall checks.
- `openshell_gateway.py`: guest-side rollout of a verified patched gateway (`install`,
  `set-quota`, `restart`, `status`); built by `deploy/openshell/build_gateway.sh`. See
  [patched gateway build](../deploy/openshell/README.md#patched-gateway-build).
- `openshell_admissions.py`: run as root in the guest (`--checkout-id`), reads the running
  gateway's admission ledger in SQLite read-only mode and prints one JSON line of aggregate
  counts (`retained`, `quota`, `read_only: true`); name it as `native_occupancy_command` so
  `harness eval` checks headroom first. See
  [admission occupancy](../deploy/openshell/README.md#admission-occupancy).
- `check_api_schema.py`: drift between the API and `ui/openapi.json`.
- `generated.py`: writes (`--check` reports drift in) `CLAUDE.md` from `AGENTS.md`, the
  `.claude/skills/` copies of `dev-skills/` and the runtime skill catalog.
- `skill_catalog.py`: renders that catalog, `src/infosec_harness/skills/README.md`, from each
  packaged skill's frontmatter; `generated.py` calls it.
- `corpus_verify.py`: runs each corpus fixture's maintainer tests from
  `eval-corpus/verification/` against a temporary copy of the fixture (maintainers only; it
  reads the answer key in the manifest). See
  [fixture verification](../eval-corpus/README.md#fixture-verification).

`just generated-sync` and `just generated-check` run `generated.py`; `just generated-check` also
runs `check_api_schema.py`. Runtime qualification, live evaluation, zero-dispatch replay and
history export use `harness qualify`, `harness eval`, `harness replay` and
`harness export-history` (through `./dev qualify|eval|replay|export-history`). No utility
provides an alternate agent execution path.
