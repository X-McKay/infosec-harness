# Intake iteration checkpoint: v10

Frozen source was commit `c0234b056e1cd3ecb82b927d8103cf072ea8adb3`, digest `3af6db0c02e6310dbd70df7f346c291a910a4b0d6da0f11bce6452e7b21900a2`, Python 3.12.14. Production intake remains version 1.0.2 with request limit 4 and `intake-evidence/v1`; runtime behavior, thresholds, and evaluator policy remain unchanged. The checkpoint changes source identity through docs and tests only; the live results measured the frozen parent, not this checkpoint.

| Run | Evidence | Release status |
| --- | --- | --- |
| v10 baseline | Complete: 6/9 passed, 3 unknown final SDK usages, 0 budget stops. Overlay `834c5221`; effective config `6458ccbbc095e5d5`; gateway Qwen model. | Focused gates `failed`. |
| Field feedback v11 | 3 attempts; 2 scored (1 passed, 1 failed); 1 unscored cancellation; 6 unstarted; 2 unknown final SDK usages. Root stopped with SIGINT. Overlay `80ac3327`. | Observed case gate `failed`; complete candidate/release gate `not_checked`. |
| Compact prompt | 8 attempts; 7 scored (6 passed, 1 failed); 1 unscored cancellation; 1 unstarted; 2 unknown final SDK usages. Root stopped with SIGINT. Overlay `11609cde`. | Observed case gate `failed`; complete candidate/release gate `not_checked`. |
| Worked example | 4 attempts; 3 scored and passed; 1 unscored model HTTP 502; 5 unstarted; 1 unknown. Trial self-stopped after the error. Overlay `126cf701`. | Incomplete; candidate/release gate `not_checked`. |
| Worked-example readiness retry | HTTP 502; zero evaluation cases started. | Readiness failed; candidate/release gate `not_checked`. |

Feedback and compact-prompt failures are observed case evidence. The interrupted trials do not establish full candidate reliability or release qualification. HTTP 502 is an infrastructure failure, not a scored model outcome. In the baseline, all observed rejected quotes matched only after whitespace normalization; normalization never granted acceptance. No causal claim is made about prompts or model parameters. Configured model pricing is zero; hardware cost and failed/interrupted final usage remain unknown.

## Checks and remaining gates

Source-line fallback: 48 synthetic cases passed, independently reviewed (configuration `f14e052dbf73bc23`). The five canonical wire tests passed under HTTPX MockTransport; they establish client serialization only. The selected 90 tests passed with zero failures, errors, or skips. `just check`, `just generated-check`, `just dev-skills-check`, and `git diff --check` passed. Web check is `not_applicable` because there are no web changes.

Full suite, current live qualification, production request-four requalification, all 354 public quality gates, and Temporal/replay qualification are `not_checked`. Endpoint readiness failed with HTTP 502. Sealed ten are unused (`not_checked`); live Bedrock is `not_applicable` by explicit owner exclusion. Source-line and wire mocks are not production or replay evidence.

Resume with a fresh worked-example cohort after readiness succeeds; reuse no earlier scores. If it fails behavioral gates, test temperature zero separately, then source references. Repeat promising candidates, test the production request-four limit, prove required durable compatibility before promotion, and run fresh all-agent public qualification before opening the unused sealed cases.

Controllers, overlays, and raw evaluation databases remain in ignored local `.harness/validation/quality-gates/` artifacts and are not in the checkout. This checkpoint retains source, configuration, overlay, helper, and test hashes for audit; full replay still requires those local artifacts. See [the JSON checkpoint](intake-iteration-loop-v10-summary.json) for the compact machine-readable record.
