# Evidence

Each folder is one dated, point-in-time record: what was measured, on which commit, and with
which result. Its README says in one paragraph what it proves and what it does not. Records are
not rewritten to match later code (endpoint names and workstation paths were redacted on
2026-10-04, with no measurement changed); a new measurement gets a new folder. How to add one is
in [release evidence](../evaluation/RELEASE_EVIDENCE.md#writing-an-evidence-folder).

| Folder | Record |
| --- | --- |
| [2026-09-24-original-design](2026-09-24-original-design/README.md) | The original design specification and decisions log |
| [2026-09-25-live-model-validation](2026-09-25-live-model-validation/README.md) | First live-model runs, first sandboxed corpus runs, defects stubs could not show |
| [2026-09-29-harness-evolution](2026-09-29-harness-evolution/README.md) | Evolution specification and its first implementation validation |
| [2026-09-30-agent-quality](2026-09-30-agent-quality/README.md) | Live qualification sweeps, intake trials and the failed canonical checkpoint |
| [2026-10-01-openshell-feasibility](2026-10-01-openshell-feasibility/README.md) | OpenShell feasibility and the dedicated-daemon deployment revision |
| [2026-10-01-broker-implementation](2026-10-01-broker-implementation/README.md) | Broker plan, implementation record, live-provider trials and timeout rationale |
| [2026-10-01-service-environments](2026-10-01-service-environments/README.md) | Hosted service connection support |
| [2026-10-02-broker-full-eval](2026-10-02-broker-full-eval/README.md) | Full brokered evaluation and follow-up candidates |
| [2026-10-04-broker-qualification-checkpoint](2026-10-04-broker-qualification-checkpoint/README.md) | Latest assembled broker qualification measurements |
| [2026-10-04-ui-qualification-dashboard](2026-10-04-ui-qualification-dashboard/README.md) | Qualification dashboard validation |
| [2026-10-05-astra-simplification](2026-10-05-astra-simplification/README.md) | Simplification review, behavioral changes, recovery and deterministic validation |
