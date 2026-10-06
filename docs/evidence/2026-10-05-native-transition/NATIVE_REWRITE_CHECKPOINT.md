# Native rewrite checkpoint — 2026-10-05

Replaces the staged agent graph, custom broker, application database and duplicate local
execution path with one PydanticAI investigator, native Temporal durability and OpenShell
workspace/probe/model profiles. The lightweight UI now projects Temporal investigations.
No backward compatibility with the earlier workflow generations is intended.

## Evidence at this checkpoint

| Gate | Status | Evidence |
| --- | --- | --- |
| New deterministic suite | passed | 99 tests; one network test intentionally deselected; actual local Temporal required |
| Native adapter focused suite | passed | 43 tests after additional pinned API/policy regressions; mocked boundary, not native execution |
| Installed wheel/model executor closure | passed | Separate environment imports executor with provider dependencies only; skills and release policy included |
| Lint, compile and generated API/instruction drift | passed | Canonical just recipes |
| UI tests/types/production build | passed | 6 tests and Vite build; browser layout checked against real Temporal-backed API |
| Native OpenShell execution | not_checked | Gateway and dedicated daemon running; live integration resolving pinned policy, resource and launch-authentication constraints |
| Multi-language workspace image | not_checked | Qualified runsc builder hit dpkg hard-link failure; bounded corrected build in progress |
| Self-hosted Qwen inference and 36-case quality | not_checked | Endpoint not supplied; zero model dispatches |
| Independently held-out quality | not_checked | Historical stage-specific fixtures retained, not silently relabeled for the new investigator |
| Bedrock native provider | not_checked | Synthetic credential/profile integration requires native proof; not used for this task |

## Contracts and recovery

Generation v9 uses task queue `investigate-v9`; older workers and histories must drain
before deployment. Temporal owns workflow history and status. Source snapshots and
fsynced command receipts remain on durable worker storage, which must survive restart.
An interrupted dispatch without a terminal receipt is unknown and must not be resent.

Real local Temporal tests cover replay, worker restart, cancellation/deadline cleanup and
unknown side effects. Confirmed defects gained regressions: original-source bytes/mode
checks, local ancestor substitution, cancellation of the owned eval workflow, source-bound
qualification identity, native policy admission and installed dependency closure.

Final verdicts require valid source citations, cited complete successful offline probe
receipts, original-source verification and explicit target/control observations. Those
observations are self-reported; they are not independent semantic attestation. The paired
corpus and its original labels are unchanged. Its 75% task-success and zero-unsafe-negative
thresholds remain explicit in the packaged release policy.

This is a reviewable progress checkpoint, not a release-qualified system. Payload budgeting,
worker-bound qualification provenance and actual native execution remain under active review.
