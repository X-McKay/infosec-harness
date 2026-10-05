# Native runtime transition checkpoint

The simplification candidate `476fa8b` was pushed in PR #6. On 2026-10-05 the owner
requested replacing the staged graph and custom runtime/broker machinery with
OpenShell, PydanticAI, and Temporal, without backward compatibility. This checkpoint
preserves qualification results before that architectural replacement. It does not
qualify a release.

- **passed**: actual managed runsc positive/negative execution, bounded execution,
  PID/memory exhaustion, build-egress allow/deny, isolated builder, and owned cleanup.
- **passed**: PostgreSQL broker ledger, 60 tests, zero skipped, zero provider calls.
- **passed**: all eleven stub eval adapters completed; stub scores are not model quality.
- **passed**: sealed held-out bundle structural/reference validation, ten cases.
- **failed**: broker HTTPS/Temporal service qualification. The first attempt exposed
  stale fixture output types, a missing forwarded keyword, and invalid durable setup.
  The repaired fixture rerun passed 20 tests and failed three Temporal cases: interrupted
  saved-result recovery, direct-stub replay under broker configuration, and all-agent
  broker closure. Expectations and thresholds were not relaxed. Both attempts remain
  under ignored local reports; the second report SHA-256 is
  `e0ef93d86fceebfc322242f982a4822d9dd59a19125928c0774e8c4a4c58f15f`.
  It made 26 counted local mock dispatches and zero paid dispatches. Database/process/
  private fixture cleanup passed. This is not native OpenShell proof.
- **passed**: managed database, Temporal pollers, UI/API checks after refreshing stale
  services. No workflows were running before refresh. Source identity was unavailable;
  a later temporary override naming the old commit during edits is setup-only, not
  qualification evidence.
- **not_checked**: live Qwen quality, full native OpenShell, and deployment readiness.
  Self-hosted inference only is authorized; no endpoint URL has been supplied and no
  model calls have been made. The former 118-case cohort is paused for the replacement.

OpenShell v0.1.2 ARM64 archives were hash-verified. Its dedicated daemon started while
preserving shared firewall/forwarding invariants. A minimal executor built through the
qualified builder was loaded into that daemon; these setup steps alone do not establish
workload confinement or provider readiness.

The replacement must retain fail-closed isolation, bounded execution, source/evidence
provenance, cancellation/cleanup, and conservative handling of unknown external effects.
It will use fresh workflow identities; old histories remain historical evidence rather
than a compatibility target. Retired stage-specific tests must be replaced with tests of
the new contracts; end-to-end corpus labels must not be rewritten to improve scores.
