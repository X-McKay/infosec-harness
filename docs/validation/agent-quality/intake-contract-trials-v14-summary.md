# Intake contract trials through v14

Measured source: `2f090f86cc939431c3e534c5c27e1df8fef96429`; Python `3.12.14`. The reporting commit changes documentation only.

All eight candidates were stopped by the root agent after mandatory accepted-output failures. These partial cohorts do not qualify intake, and their partial pass rates are not comparable quality estimates. No candidate was promoted, no threshold or evidence guard changed, and sealed cases were not read.

| Candidate | Attempted | Scored | Passed | Cancelled | Unstarted | Unknown final usage | Request cap |
|---|---:|---:|---:|---:|---:|---:|---:|
| worked-example-r2 | 8 | 7 | 5 | 1 | 1 | 3 | 6 |
| temperature-zero-r2 | 3 | 2 | 0 | 1 | 6 | 3 | 6 |
| thinking-disabled-r2 | 4 | 3 | 0 | 1 | 5 | 4 | 6 |
| source-lines | 6 | 5 | 4 | 1 | 3 | 2 | 4 |
| line-claims | 5 | 4 | 2 | 1 | 4 | 3 | 4 |
| source-field-feedback | 8 | 7 | 6 | 1 | 1 | 2 | 4 |
| atomic-claims | 6 | 5 | 0 | 1 | 3 | 6 | 4 |
| atomic-contract-repair | 3 | 2 | 0 | 1 | 6 | 3 | 4 |

Source-reference candidates reconstructed exact source quotes; their observed failures involved support or unset-field consistency. The first atomic-claim candidate instead had 18 schema-invalid proposals and no materialized finding. Independent synthetic tests identified nonstandard confidence bounds and conflicting representation instructions. Correcting both preserved runtime acceptance and all other baseline instruction bytes, but did not establish their contribution to the live failures.

The corrected v14 trial had eight schema-invalid proposals, 48 finite `model_type` errors across known claim fields, and no materialized finding. Two attempts scored failures; one further attempt was cancelled. All final usage was unknown. No HTTP or transport failure was recorded; this does not establish comprehensive protocol health or the exact terminal SDK cause. The finite diagnostics do not reveal exact raw input shapes.

The next hypothesis is that a self-contained transported tool schema may help the model produce claim objects. Server template reference handling is not yet verified. Any new trial must declare its schema transformation and transported-schema identity while preserving the runtime types, evidence guard, model, four-request budget, and scoring rules.

Observed candidate accepted-output gates: **failed**. Complete release qualification and sealed evaluation: **not_checked**. Live Bedrock: **not_applicable** by owner exclusion. No production behavior was promoted. A new durable wire generation still requires replay and recovery validation before adoption.

The endpoint passed actual chat generation after the owner-authorized pod replacement and again at v14 readiness. The ten-token response was truncated; arithmetic correctness remains **not_checked**. See [the endpoint recovery runbook](../../runbooks/local-model-endpoint.md).

The JSON summary pins source, controller, plan, index, model, configuration, and available safe-closure hashes. Summaries are portable, but full replay requires the ignored helpers, overlays, and private evaluation databases. No portable full-replay claim is made.
