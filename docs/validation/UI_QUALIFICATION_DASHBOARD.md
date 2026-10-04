# Qualification dashboard implementation and validation

The implementation at `4014fbc` connects the production UI to typed runtime and qualification endpoints. Qualification rows come from the reviewed ledger, pinned receipts and actual dependency bytes. The persistent indicator and Settings panel show actual API configuration and bounded broker observations. Evaluations have an honest empty state, manual refresh and foreground polling. The client consistently requests operational populations; mixed-population batch counts use the same filter as their child findings.

No seed operation, demo finding, sample response or fallback result was added. Production operators must connect the API to their operational database and configure live model access. Existing offline/test tools remain explicit test profiles. Private qualification fixture databases are validation sources, not production finding stores. Historical data was not deleted or rewritten.

## Gates

| Gate | Result | Evidence |
| --- | --- | --- |
| Deterministic backend suite | passed | 3,088 passed; 39 opt-in/capability-dependent tests skipped |
| UI regressions | passed | Four filter/client tests; hostile population overrides cannot select demo/legacy data |
| Lint, compile and agent specifications | passed | `just check` |
| Generated API, instructions and skills | passed | `just generated-check` and development-skill synchronization check |
| UI format, TypeScript and production build | passed | `just ui-check` |
| Actual recorded-model API integration | passed | 82 existing live model experiments; all 11 resolved live configurations |
| Qualification projection | passed | All 11 selected semantic gates; retained counts, measured commits and verified reuse displayed |
| Broker observation | passed | Pinned owner/health/native readiness receipts, actual source/configuration hashes, strict TLS unsigned admission rejection and 16 persisted unknown holds |
| Browser interaction | passed | Qualification, runtime/settings, evaluation list/detail, refresh/polling, truncated completion and metric integration; no console warnings/errors |
| Normal production rollout | not_checked | Validation used a write-disabled connection with lifespan reconciliation disabled |
| Hosted/Kubernetes rollout | not_checked | Requires deployment-specific measured evidence |
| New full model qualification rerun | not_checked | UI/API changes did not change declared agent/broker/model/Temporal dependencies; existing measured scopes remain explicit |
| Agent/Temporal behavior version bump | not_applicable | No agent or durable workflow behavior changes |

A final failure-path correction adds two regressions for malformed nested inventories. These inputs now return `not_checked` with all 11 components unavailable rather than raising an API error. The final guard rerun passed 3,088 deterministic tests; generated contracts and UI checks also passed. The browser receipt retains its original 4014fbc measurement and 3,086-test count.

The final full deterministic run emitted 971 existing stub-model price-accounting warnings. Those isolated tests do not constitute provider or cost-accounting qualification. Capability-dependent skipped tests remain not checked by this run; earlier measured scopes are documented separately in the credential broker checkpoint.

## Real-data verification and safety

The verification API served the implemented application against the existing private qualification PostgreSQL database. Its connection enforced `default_transaction_read_only=on`; non-read HTTP methods were blocked and Uvicorn lifespan was disabled. The frontend used that API through its normal proxy and generated client. No response substitution or fixture server was used. Existing controlled graph-test records were inspected only as validation records; they were not submitted or copied into a production finding store.

The browser showed the newest complete Partial Build cohort as 9/9, while the retained truncated attempt remained 2/9 recorded and 1/2 passed. Passing component gates were not relabeled as a fresh full-system execution. The broker view distinguished retained native readiness from the live unsigned rejection check, and continued to report the 16 unresolved requests. There were no model calls, native lease operations, broker recovery calls, hold releases or data migrations in this UI validation.

The private root receipt `operational-ui-d957567-v1/committed-ui-validation-4014fbc.json` has SHA256 `524a6401afdec05b90cf3366ef7f59d1169a7120b937c1815342e53147f944fd`. It records the measured implementation source, response hashes, counts, browser checks and safety limits. Private operator bundle and provenance files are not committed or exposed through the API.

Automatic approval review rejected creating another credential file and rejected normal API startup because its lifecycle could initialize or reconcile durable state. The read-only verification avoided both actions. Production startup, submission/recovery integration and hosted rollout were not inferred from this verification.

## Recovery and deployment

The endpoints are observations: they cannot promote evidence, retry inference or release unknown holds. Invalid, missing or changed evidence yields `not_checked`; expired broker observations become stale, and failed live channel verification remains failed. Read errors suppress exception contents, and an unavailable hold count stays unavailable rather than becoming zero. No workflow replay or recovery migration is required.

Configure the operator-owned bundle and real deployment settings as described in [dashboard operations](../operations/QUALIFICATION_DASHBOARD.md). Agent qualification provenance and the remaining full-system scope stay in [the credential broker checkpoint](CREDENTIAL_BROKER_QUALIFICATION_CURRENT.md).
