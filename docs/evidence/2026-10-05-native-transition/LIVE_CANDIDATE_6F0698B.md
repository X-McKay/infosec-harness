# Live candidate 6f0698b — failed, preserved

Both PR CI jobs passed for this candidate. The final native v10 integration also
passed using actual OpenShell workspace/probe execution, PydanticAI's native Temporal
activities, identity enforcement, bound cleanup and full history replay. Its
FunctionModel made no provider calls. Private report:
`integrated-proof/investigate-v10-integrated-2d4e5afa3b6444299a57fec1bee848c4/report.json`.
SHA-256: `4da8d47cac8110f202d9b20f589224c8e2d742cde4ea532c464e808015f882bd`.

The ordinary 36-case live cohort ran on clean commit `6f0698b` with the unchanged
limits, dataset and release policy, model `Qwen3.6-35B-A3B-NVFP4`, and only the
authorized self-hosted endpoint. Its first case failed after one completed model
response. That response used 1,894 input / 218 output tokens and requested three
skills through `load_capability`. The durable `model:2` receipt has exit code zero
and complete output.

The next model activity failed before inference while revalidating the existing
native model sandbox. OpenShell returned `FAILED_PRECONDITION`: the earlier execution
had terminated and its output stream was not stored; the request was not relaunched.
The adapter reused a static execution ID for its trusted boundary observation on
every sandbox admission. The second admission consequently requested a replay of
the first check instead of a fresh observation.

This is not a model-quality result. Complete corpus is `failed`; task-success and
unsafe-negative gates are `not_checked`. The remaining 35 cases are unstarted.
Both owned sandboxes were closed, the run fence persisted, and explicit cleanup
reconciliation passed. The owned worker stopped. No inference was automatically
resent and no second inference receipt exists.

Private reports under `.harness/openshell/private/live-eval-6f0698b/`:

| Report | SHA-256 |
| --- | --- |
| `cohort-6f0698b.json` | `22dc79bc313b945dc3590ab8cb9a6235907bb4d11ece5c90e7adfc2068198e00` |
| `failure-summary.json` | `41779840105e15637c9b5a1dfb69650654c4e879b2469ea913fa4876d2edab54` |
| `first-case-failure.json` | `206ccc275da8eb8f692cae0d53712245d188f5d25420a0e61c02175f71873e79` |

The correction must give each intentional trusted admission observation its own
native request ID. Stable IDs and unknown-execution fences for model dispatch and
repository commands must remain unchanged. Repeated sandbox admission needs its own
regression and native proof before another clean candidate is evaluated.

The correction passed 58 adapter tests, including repeated admission, stable command
receipt replay and unknown-admission cleanup without resend. Native qualification
admitted the same provider-attached model sandbox twice and a third time from a new
adapter instance. The three identical trusted checks used distinct native UUIDs;
all boundary observations and exact cleanup passed, with zero inference calls.
No image, policy, provider configuration or upstream fork changed.

Private `native-repeated-model-admission-report.json` SHA-256:
`f45bc5c96d4d7066d33e6c48dbd2ba4cac4aba3640f274dd63139e277d95b496`.
Private `live-eval-6f0698b/native-replay-diagnosis.json` SHA-256:
`e8ed917c99c6267aed7c6c8593dc1c849158c0d75ab5093be803ce466b990cf0`.
