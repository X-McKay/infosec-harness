# Release qualification, 2026-10-05

`harness eval release` at commit `6020811` (branch `feature/claude-refactor`, PR #4), run from a
macOS host against `./dev`'s Lima VM (Docker with `runsc` as the default runtime, the build-egress
proxy and the gVisor builder up) and a self-hosted OpenAI-compatible gateway serving
`Qwen3.6-35B-A3B-NVFP4` at zero price. Every agent's full packaged dataset ran once; the
execution-backed build-repair case was built and checked inside the sandbox for the first time on
this branch.

**Verdict: NOT QUALIFIED.** 10 of 11 agents pass their release policy.

| Agent | Cases | Task success | Gates | Failing checks |
| --- | --- | --- | --- | --- |
| build-repair | 14/14 | 93% | failed | schema_validity_rate=0.9286!=1 |
| context | 15/15 | 87% | passed | - |
| env-planner | 10/10 | 100% | passed | - |
| intake | 9/9 | 100% | passed | - |
| partial-build | 9/9 | 100% | passed | - |
| probe-author | 10/10 | 100% | passed | - |
| probe-diagnosis | 13/13 | 92% | passed | - |
| probe-planner | 10/10 | 90% | passed | - |
| probe-repair | 10/10 | 100% | passed | - |
| recon | 9/9 | 100% | passed | - |
| verdict | 9/9 | 100% | passed | - |

build-repair fails one hard gate, `schema_validity_rate` 13/14: on
`swallowed-install-failure-must-not-survive-the-repair` the model exhausted its 16 requests
without producing a spec the validator accepted (it kept proposing an install command that hides
its own failure). That is model behaviour on this gateway model; build-repair also failed its
live gate in the last recorded qualification before this branch. partial-build's p95 model
requests sit exactly at its ceiling of 12.

What this proves: every agent completes its dataset on the current code, the gates are evaluated
by the committed policies with full provenance (no `not_checked` checks), and the sandbox
execution path works end to end on the dev VM. What it does not prove: build-repair's release
readiness, and quality on any model other than the one named above. No baselines were recorded
from this run. Reports are the sanitized release reports (`exp-*.json`) and `summary.json`; the
checkout path and the gateway hostname are replaced by placeholders.
