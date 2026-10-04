# Current broker qualification checkpoint

This checkpoint records separate measurements. It does not declare a new combined full 118 run or supersede retained failures.

| Measurement | Source | Result |
| --- | --- | --- |
| Deterministic checks | `449be68075d97e6d5469fc4c8c7b33436a016ca1` | 3006 passed, 39 skipped; check, generated and development-skill checks passed |
| Recorded-history replay | `449be68` | 39 corroborated histories passed, zero forbidden I/O; the uncorroborated history and missing env-planner 1.0.4 history remain not_checked |
| Native agents and SDK replay | `10f35e9` | Local 11 + Temporal 11 passed; all 11 captured histories replayed |
| Real graph | `10f35e9` | API, workflow, sandbox isolation and cleanup passed; three captured histories replayed |
| Current controller integration | `449be68` | Exact owned replacement recovered; loaded controller/OpenShell/transport bytes, configuration, TLS401 and old state preserved |
| Current all 11 readiness | `449be68` | All 11 contracts Ready, exact test leases Deleted; 3653 requests/954 roots/1362 lease files/16 held unknowns preserved; zero provider calls |
| Fresh Partial Build 9 | `449be68` | All 9 original cases passed; authored schema/budget/coverage/task-success/cost/request gates passed; p95 requests 10 |
| Latest full 118 attempt | `10f35e9` | Failed during Partial Build after four complete cohorts: 48 cases, 47 semantic successes; all four completed cohorts passed their authored gates |
| Earlier full 118 | `5c32ed1` | All 11 authored cohort gates passed; 116 semantic successes of 118 |
| Current state retention | `449be68` | 3713 request rows, 963 budget roots, 1371 Deleted lease files; 60 new completed requests/9 roots/9 Deleted leases; all 16 old completion_unknown holds preserved twice; native 0, provider 2 |

The latest full attempt remains failed. Its one new held Partial Build request produced a closed controller `provider_request/network` marker in a bounded time window. That window does not establish exact-request causality. Runtime state and accounting were retained; the hold was not released or retried. Provider/network reliability is unresolved.

The controller/transport change in 449be preserves optional closed diagnostic metadata across the remote error boundary. It does not change model output, thresholds, budgets, retry policy or Temporal identities. Current-source controller activation and actual all 11 readiness passed separately. The measured 10f native/graph evidence can be reused through its explicit dependency review; configured names and offline checks are not serving evidence.

The reviewed dependency sidecar carries all 11 semantic components to 449be using four complete 10f cohorts and seven complete 5c cohorts; it does not claim fresh 449be inference. The seven cohorts absent from the latest truncated attempt still have earlier 5c measurements; absence from a newer attempt does not erase that evidence. Further reuse requires a signed-off equivalence sidecar or a fresh complete cohort with the same authored cases and gates. Fresh 449be Partial Build 9 subsequently passed and replaces historical Partial Build in the selected 11-component matrix. The other selected components comprise four complete 10f cohorts and six complete 5c cohorts. The ledger retains all 15 earlier records plus the fresh Partial measurement. The assembled local acceptance names each contributing run and retains the latest failed full attempt. Fresh 449be full 118, hosted/Kubernetes qualification and broader system/network reliability remain not_checked.

The assembled local component qualification is **passed**. The selected cohorts are:

| Agent | Measured source | Semantic cases passed | Authored gates |
| --- | --- | --- | --- |
| Build Repair | `10f35e9` | 14/14 | passed |
| Context | `10f35e9` | 14/15 | passed |
| Environment Planner | `10f35e9` | 10/10 | passed |
| Intake | `10f35e9` | 9/9 | passed |
| Partial Build | `449be68` | 9/9 | passed |
| Probe Author | `5c32ed1` | 10/10 | passed |
| Probe Diagnosis | `5c32ed1` | 12/13 | passed |
| Probe Planner | `5c32ed1` | 9/10 | passed |
| Probe Repair | `5c32ed1` | 10/10 | passed |
| Recon | `5c32ed1` | 9/9 | passed |
| Verdict | `5c32ed1` | 9/9 | passed |

These are separate complete cohorts with 115 semantic successes across 118 cases. Authored thresholds remain unchanged; passing qualification does not imply perfect semantic accuracy. The tooling-only follow-up passed 29 focused tests, lint, agent validation, generated-artifact checks and development-skill checks. Runtime behavior, model settings, budgets and Temporal generations are unchanged by that follow-up, so its component evidence is retained.

## Retained local receipts

These private artifacts are intentionally excluded from Git. Hashes bind the exact saved bytes; they are historical evidence, not execution permissions.

- 449be checks: `canonical-checks-449be68-v1.json`, SHA256 `e927b60f046068fc73e36e1b4cf16a831b4037741e0a4ce9d5092da8ae34caf6`.
- 449be recorded replay: `canonical39-recorded-replay-external-449be68-v1/root-terminal.json`, SHA256 `c9a88b23afd9f28cda6b1c4457489e5424149d5cf07651949426cb1b0446c324`.
- Reviewed semantic equivalence: `component-qualification-equivalence-5c-10f-449-v3.json`, SHA256 `162729916427e675db41f00f2945502d76cd60c49587d6965b8d73c40b476cd2`.
- Current controller health: `controller-owned-created-continuation-runtime-449be68-v1/continuation-health-proof.json`, SHA256 `81b5d9e9ef4390e9d0c4b97bc23f07fd12951c9f0efbefbb0d2bdfd15d4b940d`.
- Current all 11 readiness: `current-controller-all 11-readiness-external-449be68-v2/root-terminal.json`, SHA256 `4c51bee599163fdfd9bc265587800c1574411f9c3b93a53f4e599985e951fb3e`; guest proof `fff344e4d25c856c0ace1c03cbd6ad997c11e015b6e82c23cec46e1cb41f8e4c`.
- Updated equivalence including current recorded39: `component-qualification-equivalence-5c-10f-449-v4.json`, SHA256 `725ac3a9c47c660789c3e60a7b2368c3f6f10f9d9ada258bf4d6aae1d3ec22de`; the v3 semantic measurement references remain retained.
- Assembled local component acceptance: `assembled-local-component-qualification-449be68-v1.json`, SHA256 `75d451f0f8efd8d0d6b4111ec8f191d4914ae8264d80a0befaea6a01dec055d8`.
- Fresh Partial9 model: `partial9-current-controller-actor-runtime-449be68-v1/model-root-proof.json`, SHA256 `030e007b9bfc04c13466ec71db19cb67f55b4ca9bec35973b9b3d209e163ce71`; external `557713ae67c96f9df3ef94e61ffeac45ccac52f9ff932bddbe884491fd0f0130`.
- Partial9 readonly closure: `partial9-current-controller-posttrial-external-449be68-v2/root-terminal.json`, SHA256 `4ab2ac01ed5b74054c4e5f633cb497de319d8a44286e71c7b0c6ff43f27ed383`; root `55a00da4a3262ddcf407041cc8f631d2b9a475df74d8b3c97674def386da2e22`; whole `b0f9e485bc02bf9ad0394f2e9ed7460b5c5050a1ae65a81f4c425a109964eead`.
- Latest failed model proof: `full118-current-10f35e9-actor-runtime-v1/model-root-proof.json`, SHA256 `0203a5c78523c4050ee42d90c1f9c07f1ba40c6827a20238a4a7664a9f3b96cb`.
- Saved retention reconciliation: `full118-current-10f35e9-failed-retention-saved-reconciliation-v5.json`, SHA256 `2816ba17850ca521c289997c79b7c9cedbfa0b1a25e1f70a4258bb96e3d63461`. Its original outer failure remains preserved.

All paths above are under the operator's `.harness/openshell-spike/live-qualification/`. See [component qualification](../evaluation/COMPONENT_QUALIFICATION.md) for incremental invalidation and the reviewed ledger.
