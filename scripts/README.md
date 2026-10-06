# Operator and development utilities

- `dev_setup.py`: pinned checkout-local tools, Linux VM and trusted image builder.
- `dev_sandbox_check.py`: actual runsc and build-egress acceptance for image provisioning.
- `openshell_artifacts.py`: checksum-verified native release downloads.
- `openshell_guest.py`: dedicated OpenShell daemon with explicit ownership and firewall checks.
- `control_plane_check.py`: bounded GET-only API/Temporal/UI readiness.
- `openshell_gateway.py`: guest-side rollout of a verified patched gateway (`install`,
  `set-quota`, `restart`, `status`); built by `deploy/openshell/build_gateway.sh`. See
  [patched gateway build](../deploy/openshell/README.md#patched-gateway-build).
- `check_api_schema.py`, `generated.py`: generated API and development-instruction drift.

Runtime qualification, live evaluation and zero-dispatch replay use `harness qualify`,
`harness eval` and `harness replay` (through `./dev qualify|eval|replay`).
No utility provides an alternate agent execution path.
