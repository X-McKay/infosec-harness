# Credential broker implementation records (2026-10-01 to 2026-10-02)

The [implementation and testing plan](CREDENTIAL_BROKER_IMPLEMENTATION_PLAN.md) defines phases
P0 to P8. The [implementation record](CREDENTIAL_BROKER_IMPLEMENTATION.md) tracks their gates;
[live-provider](CREDENTIAL_BROKER_LIVE_PROVIDER.md), [native rerun](CREDENTIAL_BROKER_NATIVE_RERUN.md)
and [thinking](CREDENTIAL_BROKER_THINKING.md) record live trials against one self-hosted endpoint;
[timeouts](CREDENTIAL_BROKER_TIMEOUTS.md) is the offline rationale for the 240-second provider
deadline that `src/infosec_harness/inference/timing.py` cites. They prove that deterministic,
PostgreSQL, mock-native and direct live checks passed, that native live qualification failed, and
why. They do not establish a broker rollout. Scripts they name (for example
`broker_native_diagnostic_check.py`) and the G0 prototype have since been deleted; current
runners are listed in the [runbook](../../broker/RUNBOOK.md). Endpoint names and workstation
paths were redacted on 2026-10-04.
