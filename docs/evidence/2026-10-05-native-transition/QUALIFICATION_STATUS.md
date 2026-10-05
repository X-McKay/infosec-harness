# Qualification status — 2026-10-05

Implementation candidate: `2d28974` on `feature/astra-simplification`.
PR: https://github.com/X-McKay/infosec-harness/pull/6 (target `develop`).

The rewrite is implemented and pushed. Live release qualification remains **blocked**.
A fresh cohort exposed an evidence-feedback defect, corrected in `f7b6656` with generation
v11. The following cohort captured an OpenShell policy-generation change closing the
active model tunnel; see [native provider readiness](NATIVE_PROVIDER_READINESS.md).
The next candidate gates model admission on observed native provider readiness.
No candidate is qualified for promotion, and no improved accuracy claim is supported.

## Gates

| Gate | Status | Evidence / limit |
| --- | --- | --- |
| Deterministic regression suite | passed | 233 tests with `HARNESS_TEST_REQUIRE_TEMPORAL=1` |
| Real Temporal replay, restart, cancellation and identity | passed | Includes two-worker model/tool/skill rejection, cleanup ownership and repeated cancellation |
| Lint, compilation, generated contracts and instructions | passed | Local checks and backend CI |
| Lightweight UI | passed | Five tests, types/build, browser inspection and managed control-plane readiness; web CI |
| Native workspace/probe confinement and lifecycle | passed | Actual Landlock observations, transfer, receipts, offline execution and cleanup |
| Repeated native model admission | passed | Same provider-attached sandbox, including a new adapter instance, without replaying commands |
| Minimal executor / multi-turn usage decoding | passed | New native image imports and usage-extension preservation; no inference needed for decode proof |
| Real self-hosted model dispatch | passed | Typed native smoke and completed production model responses; this is connectivity evidence only |
| Full 36-case live cohort | failed | First investigation stopped after two completed responses and a third connection loss; 35 cases unstarted |
| Task-success threshold (75%) | not_checked | No investigation completed; no quality score claimed |
| Unsafe negatives (maximum zero) | not_checked | Incomplete cohort cannot establish safety performance |
| Native package egress / offline Python dependency use | passed | Approved PyPI access, unrelated-host denial, pinned install followed by offline import |
| Reliable clean-cache Maven build | failed | Initial transfer failures preserved; IPv4 and native-CA setup eventually compiled unchanged Java, but reliability is not established |
| Independent held-out quality | not_checked | Historical staged fixtures do not qualify this architecture |
| Bedrock native provider integration | not_checked | Not exercised; authorized inference scope was self-hosted only |

Runtime Python is 17 files, approximately 3,044 lines, versus 178 files / 28,527 lines
before the rewrite (about 89% fewer lines). One PydanticAI investigator chooses skills
and tools; Temporal owns durable execution; OpenShell is the only agent execution and
provider boundary. The next candidate generation is `investigate-v11`; incompatible old
workers must drain. Durable receipts and source snapshots must remain available to
the queue's workers. See the architecture documentation for the exact recovery limits.

## Frozen native candidate

- Workspace image: `sha256:acb4868cde1d9412b58d42a7306aec44ea6fcef40571f2140884ba2c20f75949`.
- Model image: `sha256:e86f45fd6e30fc2f37d7d861f241d02110b7ad8ab32d2d9c4f732ef0ad991fd3`.
- Native configuration SHA-256: `199ed469545db9ed648b1e33d8852caec29f910290827fcd860aa51b8daed1fc`.
- Worker fingerprint: `cf1ed4876a816f6362730106c254f6f60d60dc78a294a6cfc0fb921f66cf5d89`.
- Endpoint: `https://llm.almckay.io/v1`; served model `Qwen3.6-35B-A3B-NVFP4`.
- Provider: native `ih-qwen`, attached only to the model sandbox. No public fallback.

The rebuilt model image passed actual imports and next-turn decoding of native usage
extensions. Private `usage-extension-model-import-report.json` SHA-256:
`49e0a7f1952f275fd0546163653816c2612f02cc31338c62dcff0a8e2f6d78f2`.

## Latest live failure

Workflow `investigate-v10-eval-e24bdcd26e09408a8c5d0bc924fec24a` completed two model
responses and a repository read. Model receipts `model:2` and `model:3` report
1,894/206 and 3,875/52 input/output tokens respectively. The third attempt,
`model:5`, ended with a complete executor exit-1 receipt containing
`RemoteProtocolError: Server disconnected without sending a response`, followed by
`APIConnectionError`. Its provider execution and cost are unknown. It was not resent.

The native gateway recorded the third executor starting at
`2026-10-05T17:04:37.176957Z` with 37,162 input bytes. Cleanup began around
`17:04:40.899Z`. The gateway did not record a relay restart, explicit provider-host
denial or a conclusive TLS error. Supervisor L7 logs were unavailable after normal
sandbox deletion. Absence of those logs does not establish an upstream cause.
Both owned sandboxes were closed, the run fence persisted, explicit reconciliation
passed, and the owned worker stopped. Managed Temporal and the original history remain.

Read-only Kubani log investigation and the user-requested Opus review are now
complete; see [the diagnosis](KUBANI_INFERENCE_DIAGNOSIS.md). The gateway ended the
third request after 3,022 ms without a recorded response status. A likely matching
vLLM 200 followed about one second later, but correlation and client delivery are
unproven. No responsible timeout or close path has been established. Retain native
supervisor L7 logs during a separate bounded diagnostic experiment before attempting
a fresh cohort; do not replay the unknown attempt.

Private evidence directory: `.harness/openshell/private/live-eval-v10-a4da837294d0/`.

| Report | SHA-256 |
| --- | --- |
| `cohort-2d28974.json` | `a73592bc0bd99512d6ac83265f764939b3550e6c187eb18edbeeb573b93dab38` |
| `failure-summary.json` | `b6ead589969388c25d3ee521d41687ab35586a006356b123a5515bb5679e8dff` |
| `first-case-history.json` | `6e72bdcc2319a9f47fde92504d835950d1bb203bc59d14ff47433f38d60a9d64` |
| `native-disconnect-diagnosis.json` | `f087121d8371b8aff368de7e569541da58eecc29fe40f248e5baa0d5a9edf0c3` |

Earlier failed candidates and their fixes remain in the adjacent dated evidence files.
Original labels, the 36-case cohort, limits and release thresholds were not weakened.
