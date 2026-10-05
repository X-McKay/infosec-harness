# Operator and development utilities

- `dev_setup.py`: pinned checkout-local tools, Linux VM and trusted image builder.
- `dev_sandbox_check.py`: actual runsc and build-egress acceptance for image provisioning.
- `openshell_artifacts.py`: checksum-verified native release downloads.
- `openshell_guest.py`: dedicated OpenShell daemon with explicit ownership and firewall checks.
- `control_plane_check.py`: bounded GET-only API/Temporal/UI readiness.
- `check_api_schema.py`, `generated.py`: generated API and development-instruction drift.

Runtime qualification and live evaluation use `harness qualify` and `harness eval`.
No utility provides an alternate agent execution path.
