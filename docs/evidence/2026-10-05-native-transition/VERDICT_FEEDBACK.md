# Verdict feedback regression — 2026-10-05

A new, explicitly authorized cohort at `c26b471` reached finalization without the earlier
transport failure. Seven native model requests completed with bounded exit-zero receipts.
The first investigation nevertheless failed: the model cited the abbreviated execution
ID `execute:6`, while its actual tool receipt included a tool-call suffix. Its only offline
probe failed because the model changed into `/tmp`, which is not transferred to the fresh
probe sandbox. A later workspace execution succeeded but cannot establish offline evidence.
The finalizer rejected the unsupported citation. No verdict or quality score was admitted;
35 cases remained unstarted. All three owned sandboxes closed and explicit reconciliation
passed. The failed candidate and its artifacts remain preserved.

The next candidate uses native PydanticAI output validation to return bounded feedback
about exact execution IDs and complete offline-probe evidence. It allows two output
corrections within the original overall budgets. These are new deliberation/model calls,
not retries of failed native activities. Native SDK/activity retry policies stay disabled.
The finalizer continues reconstructing evidence from durable OpenShell receipts and owns
admission. Tool documentation identifies `/workspace/repo` as the transferred directory.

The output feedback changes the agent's durable command sequence. Generation v11 uses
`investigate-v11` and prefix `investigate-v11-`; the terminal v10 cohort was reconciled
and its owned worker stopped before replacement. Existing v10 histories remain archived
and must not be replayed with the changed graph. The original unknown provider attempt
remains fenced. No claim is made that the prior transport cause has been corrected.

Current checks before the behavior change: 233 deterministic tests passed with pinned
Temporal required; one package-download test passed; lint, compilation, generated artifacts,
five UI tests and UI build passed. Fresh native workspace/probe qualification passed without
inference. These checks will be repeated as appropriate for the changed candidate.

Private evidence: `.harness/openshell/private/live-eval-v10-29a06b2c719d/`.
Supervisor logs were captured from exact native-owned containers before deletion.

| Report | SHA-256 |
| --- | --- |
| `cohort.json` | `c4f5ecd29a2ce00c8d99b70f50a44bdc45cae5187b0230c0c9860eccdc1b8275` |
| `first-case-failure.json` | `b5454285d7b823d5272e5102a547e75b9800e2b6cd7c110c93f13556b5a4ecbf` |
| `first-case-history.json` | `d3698a35c49dd3ceeb5bbb94264a3f6dad9a59304e2cd0481dc8e6c97f6a73e0` |
| `native-qualification.json` | `71d1aa3f6d1384ed2fbeab1525f7603fa8442495fc42309f692ae0f58c7e32ab` |
| `deterministic.log` | `acfa15d22ac1a7a9ab5f0b6633546abc7e64c72aa64de0b56caacceead70a78a` |
| `network-package.log` | `fff78af22493ba02c06b2380d2d501704ea7e1809c3d13831f37697315413da9` |

## Clean-cache Maven control

The first of two predeclared independent native controls failed; the second remained
unstarted. Cache emptiness, public-CA initialization and unchanged source hashes were
observed. Maven returned exit 1 with untruncated dependency-download permission errors.
Retained supervisor logs recorded expired transparent destination mappings. Cleanup
passed and no model requests were made. This narrows the package-egress failure but
does not establish its cause or a fix. Policy and TLS were not weakened.

Private report `maven-clean-cache-1.json` SHA-256:
`6225c5e260195c0356292163ef092cd4f775d88a5fc37764d72b49cb719da26a`.

## Candidate validation

The changed candidate passed lint, compilation and API/instruction/development-skill
drift checks. The full deterministic suite with `HARNESS_TEST_REQUIRE_TEMPORAL=1`
passed. Regression cases cover shortened receipt IDs, workspace execution substituted
for offline evidence, failed/contrary probes, bounded correction and Temporal restart/replay
without redispatching a command. Model executor code and native configuration are unchanged.
