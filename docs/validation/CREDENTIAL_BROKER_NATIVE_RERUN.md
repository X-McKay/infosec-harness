# Native qualification after startup-readiness correction

Status: rerun stopped after repeated Temporal transport failures; full native qualification failed; rollout disabled.

This rerun retains the [earlier qualification](CREDENTIAL_BROKER_LIVE_PROVIDER.md), including
ten uncertain requests, three saved responses and the passing eleven-agent direct baseline
and direct production graph. The user authorized work toward full native qualification on
`https://llm.almckay.io`; no paid alternate endpoint or production rollout is introduced.

## Confirmed trigger and minimal correction

A fresh native lease was observed across settings polling without inference. Actual policy,
image, provider attachment and process confinement were verified. The owned supervisor
reported an unchanged configuration revision, `policy_changed: false`, and
`provider_env_changed: true`. The ledger remained at thirteen rows and the lease was deleted.
Independent review reproduced the fixed-category interpretation from the retained private log.
This supplies the redundant-refresh trigger signature alongside the earlier captured native
stale-generation relay closure.

OpenShell [issue #3809](https://github.com/NVIDIA/OpenShell/issues/3809) and
[fix #3819](https://github.com/NVIDIA/OpenShell/pull/3819) identify the startup defect:
captured provider credentials were installed without seeding the readiness tracker. An
unchanged poll therefore refetched the environment and reactivated policy, invalidating
active streams. The fix is 29 commits after pinned release source
`6648bd0c290efbc41ba131ee9831ee45cd431f94`.

Only the exact [upstream fix](https://github.com/NVIDIA/OpenShell/commit/b8932d43be0c9a4b669fa27b6abc57a389cd2222)
is backported onto that pinned source. Independent comparison of 1,889 source files found
only `crates/openshell-supervisor/src/lib.rs` changed; Cargo.lock, OPA and relay guards are
unchanged. Original release hashes remain in `.dev-tools/openshell.json`. The separate
backport metadata, public patch and build recipe distinguish this derivative from an official
release. A changed immutable supervisor image requires fresh full-contract identities;
old requests and histories cannot be rebound or redispatched.

## Preparatory failures retained

The restored gateway initially lacked the local launch-authentication bundle reference.
The original setting was restored; launch authentication was not relaxed. A controller
Python source-path error was corrected before inference. All preparatory outcomes remain
in private logs.

The first backport passed source regressions but failed actual supervisor startup because
`libgcc_s.so.1` was absent from the minimal runtime. Its image and binary are retained as
failed preparatory artifacts. The corrected build uses upstream's GNU release
staging, pinned Zig/cargo-zigbuild and glibc 2.28 floor, without adding runtime libraries.
Its loader check and actual native startup passed. A fresh 35-second observation showed no
redundant provider refresh. All eleven native contracts reached readiness and were deleted;
the ledger remained at thirteen rows. The controller rejected an unsigned request with HTTP 401.
Source tests do not establish native readiness.

## Frozen rerun and accounting

Fresh rerun support pins seven prior reports, their exact union of ten unknown and three
completed requests, an authoritative held-ledger proof, the original direct baseline and
manifest, and the exact model/catalog/native configuration files. A reviewed cause-resolution
proof is required before freezing or dispatch. Case inputs, datasets, settings, pricing,
budgets and expected outcomes are preserved. Ground truth stays host-only.

The finite scope is 22 fresh agent trials: all eleven agents through native LocalOps and
native Temporal, followed by one separately frozen native production graph. Per-phase
exclusive execution claims prevent reusing an executed manifest after failure or lost
acknowledgement. The graph retains its existing one-shot submission guard. Unknown requests
are never replaced, resent or released. The diagnostic controller/file-sink images are
excluded from acceptance; qualification binds the standard production executor.

## Checks before inference

The final deterministic suite passed: 2,287 tests, 40 skips, 861 warnings in 87.03 seconds.
Canonical check, generated-artifact and development-skill checks passed. Independent rerun
review and 67 focused runner/graph tests passed. Upstream readiness, startup, provider-poll,
generation and quarantine source regressions passed (48 test executions). Corrected ABI/image
and all eleven actual native readiness checks passed; inference qualification is pending.
The public recipe passed syntax checking; its equivalent private build produced the verified
artifact, but the public recipe was not separately rebuilt. UI source is unchanged.

## Live rerun outcome

Candidate source `1cd0cb9` froze pilot SHA256
`257a857393dc9467bcb0bf15542e922bd6829036b2739f8800c454ed333e8755`
and the separate graph SHA256
`fd3f9a72e6b7fec8c0af8a25f8769dbeaafd54d6a65bd6e427c14a76d733e2f2`
before inference. Independent correction/linkage review passed. All six PR CI jobs passed.

All eleven LocalOps agents passed execution, expected semantic scoring and cleanup.
Temporal completed seven started cases before a scoped SIGINT stop: four execution passes,
three semantic passes, two transport failures and one interrupted case. All seven captured
histories replayed with external I/O forbidden, all seven run scopes closed, and the owned
worker was reaped. Independent visibility found four completed and three failed workflows,
with none running. Intake execution passed but semantic scoring failed: the model identified
SQL injection without the required CWE-89. The frozen expectation was not changed.

Recon and partial-build shared an initial worker-to-controller `unavailable` transport error,
then two `pending` retries and retry exhaustion. Their durations are consistent with the
90-second client timeout; the suppressed underlying HTTPX exception does not establish its
exact cause. Retained snapshots show no redispatch of either uncertain request. A third
uncertain request arose during probe-planner cancellation. Original request identities remain
disjoint from fresh trials and all old uncertain allocations remain held. No failing trial
was repeated. The separately frozen production graph remains unsubmitted (`not_checked`).

The outer report records failure, while the interrupted nested Temporal report retains
`running`; it is incomplete evidence, not a successful acceptance report. Follow-up controlled
regressions should exercise delayed controller responses across client timeout, exact-request
retries without redispatch, bounded exhaustion and retained unknown holds, plus terminal
interruption reporting. Full native Temporal/graph qualification remains unresolved.

Live model calls do not replace deterministic fault injection, credential canaries, policy
allow/deny fixtures, process confinement checks or zero-I/O recovery/replay tests. This small
frozen case set does not establish held-out model quality or deployed tokenizer/weight
attestation. The local endpoint accepts unauthenticated requests, so upstream credential
enforcement is not established by its successful responses. Future Credential Drivers and
Content Inspection are not implemented or qualified by this rerun.

## Preserved state and cleanup

Fresh ownership-gated cleanup passed. All 73 lease records are deleted and native sandbox
inventory is empty. Four quarantined preparation intents required exact historical spec
snapshots in a cleanup-only adapter; ordinary revocation checks passed without modifying
running configuration or rebinding identities. The owned global provider, controller,
PostgreSQL containers, gateway and dedicated helper stopped; the original volume remains.
The authoritative ledger retains 54 completed responses and 13 uncertain requests, with
all 13 broker-owned uncertain holds retained. The fresh private database dump SHA256 is
`5509849363d83a32978dfbc0db97fcdf3758da8f61390281e8d233920b0a52c7`.
All ten primary container identities stayed unchanged. Actual runsc/build-egress fixtures
and primary API/web/storage/persistence/Temporal smoke passed after the stopped trials.
The previous intermittent OOM-notification reliability failure remains retained.
