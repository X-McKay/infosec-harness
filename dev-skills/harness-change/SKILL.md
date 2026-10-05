---
name: harness-change
description: Implement or revise InfoSec Harness behavior, contracts, sandbox boundaries or durable workflows.
---

Use this skill for runtime changes and confirmed defects. Read `AGENTS.md` and the
relevant runtime modules first. Runtime source and packaged agent skills live under
`src/infosec_harness/`; development instructions live under `dev-skills/`.

1. Identify the affected contract, safety boundary and durable recovery risk.
2. Make the smallest coherent change. Prefer PydanticAI, OpenShell and Temporal primitives
   to duplicate infrastructure. Treat all finding, repository and model content as untrusted.
3. Preserve fail-closed admission, bounded I/O, explicit budgets and unknown-execution fences.
   Assess retries, cancellation, idempotency, replay and worker restart.
4. Add regression tests for confirmed defects using independently justified expectations.
   Run focused tests, then `just check`, `just test`, `just generated-check` and affected UI checks.
5. Record behavior/generation changes, evidence and limitations in the review artifact.
   Workflow-breaking changes use a new task queue; old in-flight work must drain before deployment.

Never weaken thresholds, golden outcomes or isolation to make a change pass. Do not
claim a provider or runtime was verified from its name. Report gates as `passed`, `failed`,
`not_checked` or justified `not_applicable`. Dated evidence belongs under `docs/evidence/`.
