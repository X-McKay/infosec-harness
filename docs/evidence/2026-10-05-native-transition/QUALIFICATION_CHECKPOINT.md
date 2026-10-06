# Native qualification checkpoint — 2026-10-05

This checkpoint follows `7b192ac`. It records the native implementation and fixes
before the complete live model cohort; it does not claim model quality qualification.

## Change and recovery contract

Runtime Python decreased from 178 files / 28,527 lines at `5096f8e` to 17 files /
2,930 lines (89.7% fewer lines). One PydanticAI investigator selects packaged skills
and tools. Temporal owns orchestration and history; OpenShell owns sandbox execution
and model-provider access. The UI reads Temporal projections. Application persistence,
staged agents, the custom broker, fallback runtimes and obsolete OpenShell backports
have been removed.

The breaking workflow generation uses `investigate-v9`. Existing workers must drain
before deployment. Native command receipts and source snapshots require durable,
shared storage if workers move between hosts. Unknown external execution remains
fenced rather than automatically retried. Cleanup attempts every owned sandbox even
if one deletion fails. Worker identity binds runtime source, packaged skills, library
versions and configuration; evaluation rejects a different worker identity.

Model and tool payloads are bounded before native Temporal scheduling. Model responses
are bounded before activity completion. A cumulative history guard reserves room for
finalization and cleanup; all tools, including skills, execute sequentially. Workflow
execution deadlines also cover time spent waiting for an available worker. Evaluation
records failed and unstarted cases and bounds cancellation reconciliation.

## Native evidence

Deterministic qualification passed with `HARNESS_TEST_REQUIRE_TEMPORAL=1`, including
actual local Temporal replay, worker restart, cancellation, unknown-execution fences,
payload/history limits and model-input provenance. Lint, compilation, generated API
and instruction drift checks passed. The lightweight UI's five tests and production
build passed; actual managed API/Temporal/UI readiness and browser rendering passed.

The final Bookworm integration used the production workflow and agent with a
FunctionModel, actual OpenShell workspace/probe execution, dynamic skill loading,
source and receipt validation, cleanup and full Temporal history replay. It passed
without provider calls. Private report:
`integrated-proof/investigate-v9-integrated-abc7e46496674dbdad55e3f3db478a09/report.json`,
SHA-256 `0b254d3faf6d633d9f567cf13d7bb26bf8053b32c3a73010b7ccf2dfaa99f088`.

The qualified workspace candidate is
`sha256:acb4868cde1d9412b58d42a7306aec44ea6fcef40571f2140884ba2c20f75949`.
It contains Python 3.12.13, Node 18.20.4, npm 9.2.0, Java 17.0.20.1, Maven 3.8.7,
Perl 5.36.0, cpanm 1.7046, GCC 12.2 and Make 4.3.

OpenShell's native Docker workload does not have a read-only root filesystem.
Admission instead requires native Landlock `hard_requirement` and observed denial
of both direct writes into world-writable `/dev/shm` and a symlink escape into it.
Nonroot identity, zero effective capabilities, seccomp, no-new-privileges, resource
limits, absent host sockets and direct network denial are independently observed.
The exact `/dev/null` write exception is verified as character device major 1,
minor 3, with a bounded write and EOF read. No broader `/dev` write grant is allowed.

Private report paths are relative to `.harness/openshell/private/`:

| Gate | Status | Report | SHA-256 |
| --- | --- | --- | --- |
| Workspace/probe admission, transfer, execution, receipts and cleanup | passed | `final-jdk17-cli-report.json` | `e17d88dcde9d4c95edc2285ee6577389c285bd928239109ba1f360d1f6444ac0` |
| Java source/target 7 compile and execution | passed | `final-jdk17-java7-report.json` | `42034a28239a5072df29f282150a0c821d04aa47f3b13b392847435d359f009d` |
| Actual installed toolchain execution | passed | `final-jdk17-tools-report.json` | `376d2740bd523a2f23468e8de4174ed26faa93a05859dad462bc2c0fac03ac4c` |
| Minimal executor imports without provider access | passed | `corrected-model-import-report.json` | `cf0c70e73bf2db555faba5f25f03e3788aab07aaebd80be6a77c5c052976b626` |
| One native self-hosted typed model invocation | passed | `native-selfhost-smoke-report.json` | `dcf83f81d96a9d61fd130453394d5d32867213780c6425387a38f5f2cf44e58e` |

The executor candidate is
`sha256:1ea7d07bb0d92b6942e4afcbfb638fc57ce3c3c4b9e34b8b0be466d0834348ed`.
Only `__init__.py`, `model_executor.py` and locked provider dependencies are installed;
worker, repository, Temporal and OpenShell administration modules are absent.

Failed image candidates remain in private evidence. The initial Java 21 image could
not compile the corpus's Java 7 source target; the Bookworm Java 17 image fixes that
without changing the corpus. The first minimal executor copied root-only files;
explicit image file permissions fix nonroot imports. Maven exposed the missing
`/dev/null` permission, now covered by mandatory admission checks and regression tests.

## Live evaluation contract and limitations

Only the user-authorized self-hosted endpoint `https://llm.almckay.io/v1` is permitted.
Its model listing advertises `Qwen3.6-35B-A3B-NVFP4`; this identifies the served model
name, not independent verification of model weights. Native provider attachment is
restricted to the model sandbox. There is no public-provider fallback.
The initial typed smoke used one dispatch attempt, `max_tokens=1024`, 30 input tokens
and 354 output tokens (332 reasoning tokens), completing in 3.672 seconds. Schema
validation, native confinement, provider attachment, durable receipt and cleanup
passed. It was a connectivity/schema check, not an investigation quality evaluation.
Its native configuration SHA-256 was
`22cf4b0046ecb39584cb90a4e6ec5a20f109e3bc879df842866077dbae2d4dcc`.

The full cohort remains 36 cases, a minimum success rate of 0.75 and zero unsafe
negative verdicts. Dataset SHA-256:
`5aa87683d75664a8363665b68c46ff764975373f53dd3ddd49d20a10ee460425`.
Release policy SHA-256:
`49c958280a8832783cfc57aca9f75ae4798605bc6eb3a86aec67716639351967`.
Golden labels and host variant paths are excluded from model inputs. Original source
capture provenance is retained. No thresholds or golden outcomes were changed.

At this checkpoint, full live cohort quality and independent held-out qualification
are `not_checked`. Bedrock credential-provider integration is `not_checked` and is
outside the authorized inference scope. Mocked model and native integration tests
do not count as quality evidence. Probe control markers remain model-authored claims;
actual offline execution and source citations are checked, but semantic adequacy is
not independently proven. A post-execution source check cannot detect a modification
that was restored before inspection. These limits prevent a claim of universal
robustness or zero remaining technical debt.
