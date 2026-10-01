# Canonical qualification checkpoint — 2026-09-30

The run ended without qualification. It measured commit `880a7bfe61e238fcd738d1e5e5c86d4e28f2a039`, source digest `b837896092295e35fc02c83463b0700562a7423a591576e367629a79fe4212f2`, Python 3.12.14, and evaluator `deterministic-agent-output-v11`, using the local gateway model `Qwen3.6-35B-A3B-NVFP4`.

The sequential controller finished 25 of 33 public suites in 16,194.656 seconds (about 4.5 hours). It persisted 265 attempted runs and 264 scored attempts out of 354 planned public attempts. No held-out phase was admitted. The eight-hour public wall cap was not the stopping condition; the third build-repair CLI exited unsuccessfully. No scores are pooled or carried forward into another qualification.

| Evidence or gate | Status | Result |
|---|---|---|
| Full qualification | failed | Public phase incomplete and mandatory gates not all passed |
| Frozen source/controller provenance | passed | Source stayed unchanged throughout execution |
| Intake, each of three cohorts | passed | Each independently scored 9/9; all eight gates passed |
| Probe-author cohort 2 budget gate | failed | One genuine request-limit stop; 9/10 task successes |
| Build-repair cohort 3 completion | failed | `ModelHTTPError`, HTTP 502; one attempted, zero scored |
| Context/probe-planner original diagnostic closure | failed | Controller Unicode hashing defect affected 50 scored cases |
| Independent typed config/budget audit of those 50 cases | passed | Recorded runtime configuration and budgets match canonical derivation |
| Held-out qualification | not_checked | Requires all public gates to pass first |
| Post-run endpoint serving | passed | Actual chat generated text, HTTP 200; no pod restart |
| Post-run arithmetic correctness | not_checked | Ten-token health response ended at its length limit |
| Live Bedrock | not_applicable | Excluded by repository owner |
| Merge to main | not_checked | Not performed; release qualification remains failed |

## Request-limit failure

Probe-author's stopped attempt reached its effective 16-request cap in 69.49 seconds. All 16 model responses carried usage: 169,151 input tokens and 4,342 output tokens. The terminal `usage_unknown=1` status reflects the absence of an accepted terminal result; it must remain unknown in the release accounting, despite the available per-response telemetry.

The attempt made 19 tool calls, including seven repeated identical `describe_callables` calls. Other configured limits were not binding. The remaining nine cases in that cohort passed using 3–9 requests; the first cohort passed 10/10 with at most six requests. Configuration, model, and budget digests agree across these cohorts. Repetition is observed, but its causal role is not established from this one failure. Preserve the zero-budget-stop gate and test one small loop-mitigation change under the same limits before considering a budget increase.

## Diagnostic controller defect

The frozen controller hashes a reconstructed effective configuration using generic `json.dumps`, whose default `ensure_ascii=True` differs from canonical configuration serialization (`ensure_ascii=False`). Non-ASCII instructions in context and probe-planner trigger the mismatch. All 50 scored cases in their first two cohorts match independently derived `BudgetResolution` values/digests and `ResolvedAgentConfig.digest`. An ASCII control agrees with both hashing methods; a synthetic Unicode control reproduces the controller mismatch.

The proposed correction is to use the typed `ResolvedAgentConfig.digest` and `BudgetResolution.digest` in diagnostic closure, leaving separately declared manifest hashing unchanged. Add independently authored Unicode and ASCII regressions, then version and refreeze a new controller packet. This correction has not been implemented. It needs no runtime behavior or evaluator version change if confined to the external controller. Preserve the original frozen packet and failed run; correcting this observation defect cannot qualify an incomplete run or erase its independent budget failure.

## Preserved evidence and next work

The [numeric checkpoint](canonical-qualification-20260930.json) records all 33 suite gate statuses, the 26 observed suite metrics, and SHA-256 values for the plan, final index, public index, and closed database. Complete artifacts remain under the original worktree's ignored directory:

```text
.harness/validation/quality-gates/full-canonical-20260930T155930Z-2whsyifq/
```

The checkpoint is not a portable replay bundle. Controllers, frozen manifests, logs, databases, temporary sealed execution snapshots, and environment state are not committed. The original sealed fixture bundle is already tracked in the repository; it was not semantically read or admitted in this run. See [the root handoff](../../../handoff.md) for continuation paths, checks, operational limits, and the ordered next steps. The documentation checkpoint changes the repository identity; the measured runtime commit remains `880a7bf`.

Pre-run deterministic validation passed: 1,846 tests, `just check`, `just generated-check`, and `just dev-skills-check`; actual runsc/build-egress preflight and managed local Temporal replay/recovery checks passed. These do not replace live all-agent qualification or establish live Bedrock/Temporal-model cancellation evidence.
