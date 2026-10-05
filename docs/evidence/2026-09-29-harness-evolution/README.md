# Harness evolution specification and implementation validation (2026-09-29)

[`HARNESS_EVOLUTION_SPEC.md`](HARNESS_EVOLUTION_SPEC.md) is the reviewed proposal (v0.4.2)
behind the reliability, evaluation, developer-experience and UI work, with its requirement IDs
(EVID, SNAP, SBX, ENV, INF, DUR, EVAL, CAL, DX, UI) and review decisions D01 to D13.
[`IMPLEMENTATION_VALIDATION.md`](IMPLEMENTATION_VALIDATION.md) and
`harness-evolution-evidence.json` record the gate results of its first implementation: the
deterministic suite, PostgreSQL migrations, and an actual isolated build and probe under runsc in
the managed macOS VM passed; clean Linux onboarding was `not_checked`, the live
OpenAI-compatible profile `failed`, and live Bedrock was excluded. Its decisions are history,
not current contracts: some were superseded (development skills are no longer generated copies,
budget-stop metrics were replaced by `budget_exhausted_count`, intake generations are no longer
retained). Endpoint names and workstation paths were redacted on 2026-10-04.
