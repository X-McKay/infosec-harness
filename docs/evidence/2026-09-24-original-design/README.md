# Original design specification (2026-09-24)

[`SPEC.md`](SPEC.md) is the first design review draft of the triage harness and its decisions
log; code comments still cite its decision numbers (D2 sandbox, D6 budgets, D13 comment-only
write-back, D14 build egress). It records why the system has its shape. It does not describe the
current implementation: it names a MinIO artifact store, a Kubernetes probe runner, TanStack
Table, and prompts that insert strings verbatim, none of which is true now. For current behavior
read [the triage system](../../architecture/TRIAGE_SYSTEM.md), the
[threat model](../../threat-models/triage-system.md) and the package docstrings.
