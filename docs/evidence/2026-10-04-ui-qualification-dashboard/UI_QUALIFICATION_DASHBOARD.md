# Qualification dashboard implementation and validation

The implementation at `4014fbc` connects the production UI to typed runtime and qualification endpoints. Qualification rows come from the reviewed ledger, pinned receipts and actual dependency bytes. The persistent indicator and Settings panel show actual API configuration and bounded broker observations. Evaluations have an honest empty state, manual refresh and foreground polling. The client consistently requests operational populations; mixed-population batch counts use the same filter as their child findings.

No seed operation, demo finding, sample response or fallback result was added. Production operators must connect the API to their operational database and configure live model access. Existing offline/test tools remain explicit test profiles. Private qualification fixture databases are validation sources, not production finding stores. Historical data was not deleted or rewritten.

## Gates

| Gate | Result | Evidence |
| --- | --- | --- |
| Deterministic backend suite | passed | 3,133 passed; 39 opt-in/capability-dependent tests skipped |
| UI regressions | passed | Four filter/client tests; hostile population overrides cannot select demo/legacy data |
| Lint, compile and agent specifications | passed | `just check` |
| Generated API, instructions and skills | passed | `just generated-check` and development-skill synchronization check |
| UI format, TypeScript and production build | passed | `just ui-check` |
| Actual recorded-model API integration | passed | 82 existing live model experiments; all 11 resolved live configurations |
| Qualification projection | passed | All 11 selected semantic gates; retained counts, measured commits and verified reuse displayed |
| Broker observation | passed | Pinned owner/health/native readiness receipts, actual source/configuration hashes, strict TLS unsigned admission rejection and 16 persisted unknown holds |
| Browser interaction | passed | Qualification, runtime/settings, evaluation list/detail, refresh/polling, truncated completion and metric integration; no console warnings/errors |
| Normal local API startup and UI rollout | passed | Ordinary migration/lifespan, managed service recreation, non-seeding UI reload and real-data live API startup |
| Packaged nginx web deployment | passed | Actual container build, nginx syntax, API proxy, SPA routes/assets and no-store headers |
| Hosted/Kubernetes rollout | not_checked | Requires deployment-specific measured evidence |
| New full model qualification rerun | not_checked | UI/API changes did not change declared agent/broker/model/Temporal dependencies; existing measured scopes remain explicit |
| Agent/Temporal behavior version bump | not_applicable | No agent or durable workflow behavior changes |

A final failure-path correction adds two regressions for malformed nested inventories. These inputs now return `not_checked` with all 11 components unavailable rather than raising an API error. The earlier guard rerun passed 3,088 deterministic tests; generated contracts and UI checks also passed. The browser receipt retains its original 4014fbc measurement and 3,086-test count.

The final 3,133-test deterministic run emitted 971 existing stub-model price-accounting warnings. Those isolated tests do not constitute provider or cost-accounting qualification. Capability-dependent skipped tests remain not checked by this run; earlier measured scopes are documented separately in the credential broker checkpoint.

## Real-data verification and safety

The verification API served the implemented application against the existing private qualification PostgreSQL database. Its connection enforced `default_transaction_read_only=on`; non-read HTTP methods were blocked and Uvicorn lifespan was disabled. The frontend used that API through its normal proxy and generated client. No response substitution or fixture server was used. Existing controlled graph-test records were inspected only as validation records; they were not submitted or copied into a production finding store.

The browser showed the newest complete Partial Build cohort as 9/9, while the retained truncated attempt remained 2/9 recorded and 1/2 passed. Passing component gates were not relabeled as a fresh full-system execution. The broker view distinguished retained native readiness from the live unsigned rejection check, and continued to report the 16 unresolved requests. There were no model calls, native lease operations, broker recovery calls, hold releases or data migrations in this UI validation.

The private root receipt `operational-ui-d957567-v1/committed-ui-validation-4014fbc.json` has SHA256 `524a6401afdec05b90cf3366ef7f59d1169a7120b937c1815342e53147f944fd`. It records the measured implementation source, response hashes, counts, browser checks and safety limits. Private operator bundle and provenance files are not committed or exposed through the API.

The earlier read-only validation did not establish normal startup. The subsequent local deployment validation below closes that gap. Hosted rollout is still not inferred from local results.

## Recovery and deployment

The endpoints are observations: they cannot promote evidence, retry inference or release unknown holds. Invalid, missing or changed evidence yields `not_checked`; expired broker observations become stale, and failed live channel verification remains failed. Read errors suppress exception contents, and an unavailable hold count stays unavailable rather than becoming zero. No workflow replay or recovery migration is required.

Configure the operator-owned bundle and real deployment settings as described in [dashboard operations](../../operations/QUALIFICATION_DASHBOARD.md). Agent qualification provenance and the remaining full-system scope stay in [the credential broker checkpoint](../2026-10-04-broker-qualification-checkpoint/CREDENTIAL_BROKER_QUALIFICATION_CURRENT.md).

## Normal deployment validation (2026-10-04)

The running development API was still an old process: the web loaded but the new status routes returned 404. API and web were recreated through the ordinary Compose commands at implementation source `0dbce33140580fa0f224f83fa90d74e48ef2596e`. Editable installation, the migration command, application lifespan bootstrap and submission reconciliation ran normally. No wrapper or disabled lifespan was used. GET-only smoke checks passed directly and through the running web proxy; all 11 qualification rows were projected from measured receipts and verified dependencies. The managed development profile remains explicitly `stub/direct`; its operational findings, workflows and evaluation lists are empty, and historical demo records are excluded. The implementation has no seeded or fabricated fallback.

A separate ordinary-lifespan API connected to the existing live qualification PostgreSQL database and existing OpenShell catalog. Its real frontend displayed `live/brokered`, 82 recorded live evaluations, all 11 passing component gates and 16 unresolved requests. Broker status verified pinned retained native readiness plus a current strict-TLS unsigned admission rejection; it did not claim a new native lease or model execution. The complete Partial Build detail showed 9/9 recorded and passed. The retained truncated attempt showed 2/9 recorded and 1/2 passed after selection and refresh. Both local browser sessions had no console warnings or errors. The validation database's three historical controlled graph records were inspected only; no finding was submitted or copied into the operational store.

The production Dockerfile built the actual static bundle and nginx container. With the trusted web service runtime used by the managed deployment, nginx syntax, direct/proxied contracts, both referenced assets and SPA routes passed. `/api/runtime-status`, `/index.html` and `/qualification` returned `Cache-Control: no-store`. Agent execution sandbox settings were unchanged. This is packaged-web validation on local infrastructure, not hosted/Kubernetes qualification.

This exercise identified two deployment-check defects: existing unpaginated evaluation summaries exceeded the arbitrary 5 MiB response limit, and Compose restart returned before API/web startup completed. The checker now accepts bounded responses up to 16 MiB and the reload command waits within its shared deadline for transient connection/disconnect/502/503 startup failures. Contracts, component completeness, source identity and error requirements are unchanged; 404, malformed contracts and oversized responses still fail. Regression cases cover both confirmed failures.

Normal lifecycle regression tests also confirmed and fixed a JSON-null submission issue: SQL `IS NOT NULL` admits JSON null, but only dictionary submissions are dispatchable. SQL null, JSON null and other malformed payloads are retained without dispatch. Valid pending submissions and cancellation reconciliation retain their behavior. Startup ordering and task cancellation/join on shutdown have regression coverage. No agent prompt, model configuration, broker adapter or Temporal workflow definition changed; no behavior-version bump or historical replay reinterpretation is required. Skipped malformed rows remain available for explicit operator diagnosis rather than being repaired or silently promoted.

Before stopping the old UI/API, after fencing them, after normal deployment, and after live integration/reload, read-only database snapshots agreed exactly for batch/run rows, budget ledgers and complete unresolved-request rows. Both schemas were current with no pending submissions or cancellations. All 16 unknown holds stayed unchanged; no inference retry, recovery, hold release, native lease operation, model call or seed operation was performed. The migration command ran against the already-current schema and made no schema or data changes. The private deployment receipt records these hashes and service identities. Temporary validation services were removed; the ordinary managed API/web remain available.

A fresh full model suite, hosted/Kubernetes rollout, and missing historical replay coverage remain `not_checked`. The component ledger continues to distinguish measured cohorts and dependency-verified reuse from a fresh full-system run.

The private normal-deployment receipt `ui-normal-deployment-387a720-v1/normal-deployment-validation.json` has SHA256 `5380af6fab72dea6cbcc197659e89ee264b0444e59ec7adaaae63b5101727c0d`. It records response hashes, exact checker bytes, normal service identities, unchanged-store snapshots, browser observations and cleanup.

## First UI usability batch (2026-10-04)

The runtime indicator and Settings share configured model names and separately recorded model connectivity. An unconfigured broker displays `Not enabled` with no stale or unresolved-request alert. Qualification places the active-profile status and remaining gaps above retained component evidence; passed source/component receipts cannot qualify a different active transport/model profile. Model connectivity receipts bind actual configuration and broker catalog bytes, source commit, mode and transport; malformed, changed, future or expired records cannot become current connectivity evidence. Browser refresh never invokes inference.

Finding details retain operational filters, metric bounds and queue offset in the URL. Previous/next reads filtered pages, including non-aligned offsets such as the workflow list's 10-row pages versus the queue's 25-row pages. A regression prevents overlapping previous ranges from selecting a later finding. Missing selection membership never invents neighbors. Finding-specific draft reviews reset when navigation selects another finding.

Workflows show recorded status/phase counts, conservative acceptance/completion timing and last persisted activity. Batches expand into paginated findings. Read-model regressions independently verify mixed-population isolation, event filtering, terminal-batch completion and unavailable legacy/missing timestamps. No records were seeded to populate the current empty operational views.

Browser validation against retained graph records confirmed the completed native batch's 288.3-second duration, expansion into its one recorded finding, return to the same batch filter, and progression from finding 1/3 to 2/3 in a search-filtered queue with `SQL` restored on return. The qualification view showed active-profile `not_checked` separately from passed retained component evidence. The validation session logged no console warnings or errors and was stopped afterward. These historical controlled graph records stayed in the separate validation database.

The additions affect public read contracts and generated clients only. They do not alter model settings, agent outputs, budgets, sandbox permissions, workflow execution or historical retry/replay identity; no behavior-version bump or state migration is required. Hosted rollout and a fresh full model qualification cohort remain `not_checked`.

First-batch gates: deterministic suite `passed` (3,149 tests; 39 opt-in/capability-dependent skips), UI regressions `passed` (20 tests), lint/compile/agent specs `passed`, generated contracts/instructions/skills `passed`, UI formatting/TypeScript/production build `passed`, retained-record browser validation `passed`. The 971 existing isolated price-accounting warnings remain unrelated to provider qualification.

## UI organization cleanup (2026-10-04)

The approved UI cleanup centralizes query keys and shared fetch options without changing
polling timers, operational population filtering, or review invalidation targets. Typed
HTTP errors distinguish genuine 404 responses from network errors whose message happens
to begin with 404. Run and batch activity helpers retain their intentionally different
unknown-state policies. A shared timestamp formatter renders absent or malformed values
as `Unavailable` and retains locale formatting for valid recorded times.

Finding Detail now delegates controlled review presentation, evidence cards and event
history to focused components. The route retains draft state, run-change resets, mutation
ownership and navigation. Evaluation metric, gate, cohort and resource interpretation
lives in a React-independent module; report exports remain compatible and charts no
longer import their types from report presentation.

Validation gates: UI regressions `passed` (34 tests, including cache deduplication,
review invalidation, HTTP failure classification, pagination, timestamp and evaluation
interpretation); deterministic harness suite `passed` (3,149 tests; 39 capability-dependent
skips); repository checks, generated artifacts and development skills `passed`; UI
formatting, TypeScript and production build `passed`; independent diff review `passed`.
Browser validation against retained records confirmed filter restoration, finding 1/3
to 2/3 navigation, unsaved reason/override reset with reviewer persistence, evidence and
event sections, recorded evaluation gates, and unchanged 288.3-second workflow timing.
No console warnings/errors were observed. No review was saved, findings seeded, or model
requests made. Before/after read-only snapshots matched findings, budgets and all 16
unresolved broker holds. Temporary validation services were stopped.

API schemas, agent execution, model settings, sandbox permissions and durable workflow
identities are unchanged. Runtime behavior/provenance version changes and replay/recovery
migration are `not_applicable`. Fresh full-model and hosted/Kubernetes qualification are
`not_checked` by this UI-only cleanup; existing qualification evidence is not promoted.

## API evidence organization cleanup (2026-10-04)

`api/status.py` now contains thin endpoint composition. Evidence byte/reference/bundle
reading lives in `api/evidence_io.py`; qualification projection, broker observations,
and model connectivity receipts live in their respective scoped modules. Internal
receipt annotations describe the structures without coercion or replacing the existing
runtime validation. Tests patch the new owning modules rather than compatibility aliases.

Independent review compared the extracted validation bodies with the prior implementation
and confirmed unchanged behavior after renaming and annotations. Exact fields, strict
integer checks, duplicate-key rejection, regular bounded file reads, source/configuration
hash binding, expiry, source inventory and native contract checks remain intact. Unsigned
controller probes retain their cache identity, 30-second cache, three-second bounds,
1,024-byte response cap, verified TLS, disabled environment proxy/redirects and absence of
client credentials. A failed database read still leaves unresolved requests unavailable;
stale readiness cannot be promoted by a reachable channel. Exceptions remain sanitized.

Focused security/connectivity gates `passed` (61 tests), including two real-file regressions
that feed ambiguous nested JSON or changed referenced bytes through both extracted
projections and ensure no controller probe is attempted. Full deterministic suite `passed`
(3,151 tests; 39 capability-dependent skips). Repository, generated contract/instruction/skill
and UI checks `passed` (34 UI tests and production build). Real GET-only endpoint validation
against retained data `passed`: both response contracts, all 11 component projections and
16 unresolved holds were preserved, and active-profile qualification remained `not_checked`.
Exact before/after snapshots of stored findings, budgets and unresolved requests matched.
The temporary validation API was stopped; no model request or broker recovery operation ran.

Public API schemas and agent/model/executor/workflow behavior are unchanged. Behavior or
provenance version changes, database migration and durable replay/recovery migration are
`not_applicable`. Fresh full-model and hosted/Kubernetes qualification remain `not_checked`
by this organization-only change. No existing qualification evidence is promoted.

## Supported service validation commands (2026-10-04)

`./dev validate` checks the running managed stack; `just validate-services` checks an
explicitly configured local or hosted environment. The default path only reads existing
state: database/schema head, recent workflow/activity pollers, source/profile consistency,
API contracts, actual UI assets and the same-origin proxy. It does not bootstrap services,
migrate, seed, dispatch, recover or import the durable worker to inspect its configuration.
The managed path executes inside the existing worker without changing its environment.

Explicit `--model` adds one configured direct OpenAI-compatible verdict request using
PydanticAI closed structured output and zero retries. Brokered, stub and unsupported
provider profiles remain `not_checked` without inference or fallback. Errors stay sanitized;
unknown usage remains unknown. Optional exact-profile connectivity receipts reuse the
existing API/UI contract, strict fields, source/configuration binding and expiry. Reports
and receipts are private atomic files; invalid destinations are refused before inference.
A failed request preserves previous evidence and publishes its current result separately.

Focused regressions `passed` (80 tests): SQLite read-only behavior, schema checks,
TLS connector reuse, poller freshness/identity, cached configuration drift, one-call output,
timeouts, error privacy, strict receipt validation, unsafe paths, atomic publication failures,
profile mismatch and refusal without inference. Full deterministic suite `passed` (3,225
tests; 39 capability-dependent skips), followed by the complete focused run covering the
final two additional path regressions. Repository/generated/skill checks and UI checks
`passed` (34 UI tests and production build).

Actual managed service checks `passed`, and the configured `<self-hosted-endpoint>` backend
returned the required structured result in one request. Offline validation correctly
reported every gate `not_checked` without contacting services. Exact before/after snapshots
of operational and retained-broker findings, budgets and all 16 unresolved holds matched.
No findings or broker recovery actions were submitted.

These are service connectivity checks, not qualification promotion. Public API schemas,
agent behavior, model configuration, executor boundaries and durable workflow identities
are unchanged. Behavior/provenance version changes and replay/recovery migration are
`not_applicable`. Fresh full-agent, native broker, sandbox/artifact and hosted/Kubernetes
qualification remain `not_checked` by this batch; existing component evidence is preserved.
