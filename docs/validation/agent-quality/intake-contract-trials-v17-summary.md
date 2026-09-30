# Intake contract trials through v17

Measured source: `df6c190dd7ee2382003d85c25fecc927ffa2884b`; Python `3.12.14`. These are prototype experiments, not qualification of the canonical implementation.

| Cohort | Attempted | Scored | Passed | Required gates | p95 requests |
|---|---:|---:|---:|---|---:|
| v15 inline schema | 9 | 9 | 9 | passed | 2 |
| v15 fresh repeat | 9 | 9 | 8 | failed: adversarial safety | 2 |
| v16 description wording | 9 | 9 | 8 | failed: adversarial safety | 1 |
| v17 temperature zero | 9 | 9 | 9 | passed | 2 |
| v17 fresh repeat | 9 | 9 | 9 | passed | 1 |

The selected candidate uses the original v15 instructions, atomic source references, an inline OpenAI tool schema, and temperature `0.0`. The v16 wording is not selected. No evidence guard, expected outcome, request budget, or qualification threshold changed. Each cohort was scored separately; scores are not pooled or reused for release qualification. Sealed cases were not read.

The first v17 cohort had one evidence-guard rejection followed by a correction. The repeat had none. Both cohorts had known usage, no budget violations, and clean controller closure. Neither establishes that the private server honored temperature or that temperature caused the improvement.

Two prelaunch artifact defects were corrected before inference: the v17 overlay builder omitted its declared temperature, and an earlier v16 configuration pin was stale. A separate repeat observer rejected the valid repeat directory prefix and omitted explicit predecessor-certificate verification. Its frozen bytes were preserved; a separately hashed corrected observer verified closure without changing the running controller, source, or scores.

Canonical integration and durable replay validation are **passed**. The complete deterministic suite passed: **1,846 tests**, with no failures or skips (100.73 seconds). `just check`, `just generated-check`, and `just dev-skills-check` passed. Installed-wheel checks cover retained generations; actual local Temporal tests cover completed-history replay and pending/retry frontiers. Bedrock factory behavior was mocked; no live Bedrock qualification was performed. Web checks are **not_applicable**, because this change has no UI edits. Fresh all-agent qualification (354 public case runs followed by 10 sealed cases only if public gates pass) is **not_checked**. Live Bedrock is **not_applicable**, by owner exclusion. Historical failures remain part of the evidence.

The accompanying JSON records identities and safe artifact hashes. Complete reproduction also requires the ignored controllers, overlays, and evaluation databases; these summaries alone do not provide portable replay.


The implementation advances intake to `1.0.3`, uses execution `intake-output-v3` and entry marker `intake-atomic-inline-v1`, and advances the evaluator to `deterministic-agent-output-v11`. The previous full specification is retained byte-for-byte (SHA-256 `39a68a0f21bdb3c2c8c0e10881cde0dab4b0354aae8cff0e83567ee6932b5da3`). Current instructions and schema match the selected prototype; server temperature application remains unverified.

Replay-only blocking preserves completed activity history and prevents fresh historical provider operations, including a pending semantic retry. Old workflows reaching a live frontier require a new workflow; arbitrary historical overlays are not reconstructed. Accounting uses the selected generation before reservation, retains the existing retry ceilings, and uses the unchanged cancellation/settlement and idempotency paths. Existing managed recovery and cancellation tests passed; live-provider cancellation is **not_checked**.

Initial checks and failed test attempts were preserved. One new mock test repopulated provider settings after cleanup; an independent restoration regression now protects against that leak. The final complete suite ran after the fix. Bounded proposal summaries also now report unknown capture when no output proposal was captured; this observation change does not alter scoring or acceptance.
