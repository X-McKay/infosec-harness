# Operator and development utilities

- `dev_setup.py`: pinned checkout-local tools, the Linux VM that builds trusted images and hosts
  native OpenShell, the generated `dev.env`, and `ready`, the bounded GET-only API, Temporal and
  UI readiness check behind `./dev smoke`.
- `openshell_artifacts.py`: checksum-verified native release downloads.
- `openshell_guest.py`: dedicated OpenShell daemon with explicit ownership and firewall checks.
- `openshell_gateway.py`: guest-side rollout of a verified patched gateway (`install`,
  `set-quota`, `restart`, `status`); built by `deploy/openshell/build_gateway.sh`. See
  [patched gateway build](../deploy/openshell/README.md#patched-gateway-build).
- `openshell_admissions.py`: read-only native admission occupancy for `harness eval`.
- `check_api_schema.py`, `generated.py`: generated API and development-instruction drift.

Runtime qualification, live evaluation, zero-dispatch replay and history export use
`harness qualify`, `harness eval`, `harness replay` and `harness export-history` (through
`./dev qualify|eval|replay|export-history`). No utility provides an alternate agent execution
path.
