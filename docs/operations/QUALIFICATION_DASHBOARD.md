# Qualification dashboard operations

The Qualification page reads `GET /api/qualification` and `GET /api/runtime-status`. Both are
read-only projections plus one bounded, unsigned admission check against a configured broker
controller. Neither rescoring reports, releasing accounting holds nor generating evidence is
possible from the UI.

## Component evidence

`GET /api/qualification` reports every agent component `not_checked` with freshness
`unavailable`. Accepted agent eval results are committed under `evals/baselines/` and reviewed
with the change that produced them; the service does not measure them or promote them to runtime
evidence. The component ledger the page used to read was removed because it could not be
reproduced outside one workstation ([release evidence](../evaluation/RELEASE_EVIDENCE.md)).
Qualification evidence predating that change is under [`docs/evidence/`](../evidence/README.md).

## Broker observation

Configure the real broker catalog through `HARNESS_BROKER_CONFIG`. Configuration alone establishes only `configured: true`. Without a valid observation the broker remains `not_checked`; an unconfigured deployment defaults to `configured: false` and `not_checked`.

The version-1 broker observation has exactly `version`, `checked_at`, `valid_until`, `status`, `catalog_sha256`, `dependencies` and `evidence`. Its `evidence` contains pinned `owner`, `health` and `readiness` references. These trusted operator receipts must agree on source and owner, controller identity, loaded inference-module bytes, configuration identities and all 11 native contract readiness observations. The readiness receipt must attest that its exact owned test leases were deleted and native inventory returned to zero. The catalog and relevant files are checked against their retained hashes.

`HARNESS_QUALIFICATION_OBSERVATION_MAX_AGE_SECONDS` defaults to `3600` and permits values from `30` through `86400`. Observation timestamps must be timezone-aware, ordered and within this configured lifetime. Expired observations are labeled stale and report `not_checked`; increasing the limit does not create a new measurement.

For a valid observation, runtime status also makes a bounded credential-free request to the configured controller: TLS verification uses its configured CA, redirects and environment proxies are disabled, and unsigned `POST /v1/infer` with `{}` must return exactly `401` with the auth rejection. The probe is cached for up to 30 seconds and makes no model call. It confirms the live rejection channel; it is not a fresh native sandbox/readiness test and does not renew the retained observation. A failed live channel check reports failed; invalid or unavailable evidence reports `not_checked`.

The runtime response exposes environment, model mode, assessment transport, API source label, database backend name, Temporal TLS/plaintext mode and bounded broker metadata. It does not expose credentials, connection strings, catalog paths, private receipt paths, raw exceptions or model payloads. Environment and mode labels describe configuration, not qualification evidence.

`unresolved_requests` counts persisted `completion_unknown` requests without a valid conservative operator closure audit. `conservatively_closed_requests` separately counts audited loss acceptances; those outcomes remain unknown and their full reserved operation budgets have been charged. An unavailable count is displayed as unavailable, not zero. These requests retain their accounting holds. Refreshing the dashboard does not resend, retry, reconcile or release them; recovery requires the existing explicit operator process and exact request provenance.

## Operational UI behavior

The production client always requests `population=operational` for batches, runs, metrics and evaluations, including their detail views. URL/search population overrides cannot select demo or legacy data. Selected batch finding/status/verdict counts cover only matching runs; the shared batch budget remains batch-wide. Existing stored data is retained, and unscoped API callers preserve their compatibility behavior.

The client never seeds demo findings, sample results or fallback fixture data. Production APIs must use the operational store: controlled qualification/graph fixture databases remain separate validation sources and must not be connected as the production finding store. Population filtering uses persisted provenance; it cannot determine whether an incorrectly tagged historical record was fabricated. Set `HARNESS_MODEL_MODE=live` and the actual model/broker configuration for operational deployments; explicit stub/offline development and isolated test profiles remain test tools. An empty operational database displays an honest empty state. Evaluations offer manual refresh and foreground polling every 10 seconds, including when the list is empty; active evaluation detail also polls. Qualification and runtime observations refresh every 30 seconds, and Qualification's Refresh button refreshes both. Background polling is disabled. Fetch errors are visible and do not manufacture successful observations.

The persistent environment/mode indicator and Settings runtime panel use the same real runtime response. They do not hardcode a local environment or infer readiness from a configured provider/runtime name.

## Contract and recovery impact

These endpoints and views are read-only projections, plus the bounded unsigned admission check. They do not alter agent behavior, output contracts, budgets, thresholds, Temporal activity identities or workflow histories. No durable generation/version bump or workflow recovery migration is introduced by the dashboard. Its public contracts and generated clients must remain synchronized through the repository's generated-artifact checks.

## Runtime clarity and active-profile scope

Runtime and Settings display resolved model identities separately from execution evidence. An unconfigured broker displays `Not enabled`; stale observations and held-request warnings apply only to a configured broker. Component evidence and the active model/transport profile have separate statuses; active-profile qualification remains `not_checked` without independently assessed active-profile evidence.

An operator may set `HARNESS_MODEL_CONNECTION_OBSERVATION` to a credential-free receipt from an actual inference check. Exact fields: `version` (integer 1), `checked_at` (timezone-aware ISO timestamp), `source_commit` (the deployed source), `model_config_sha256` (actual model configuration file bytes), `broker_config_sha256` (actual broker catalog bytes, or null without a broker), `mode`, `transport`, and `status` (`passed` or `failed`). Only record a pass after a real request completes with the expected result. A configured provider name is insufficient. Duplicate/extra fields, mismatched profiles/source, invalid dates and unreadable evidence remain `not_checked`; checks expire after one hour. The API does not invoke a model when displaying or refreshing this observation, and its text identifies the check as operator-recorded rather than continuous health monitoring. This is connectivity evidence, not agent qualification.

## Finding navigation and recorded workflow progress

Finding detail URLs carry queue filters, metric bounds, offset and an explicit queue-context marker. Back to queue and previous/next retain this operational selection. Adjacent navigation reads the actual filtered API pages, including non-aligned offsets; absent membership or a direct link does not invent a neighbor. Finding-specific review drafts reset when selecting a different finding.

Workflows aggregate counts, current nonterminal phases and timestamps from the selected persisted child population. Demo/legacy rows and their events cannot enter operational counts or last activity. Elapsed time requires recorded acceptance timestamps for every selected finding; a terminal duration additionally requires a terminal batch and every selected completion timestamp. Missing timing remains unavailable. Last activity includes persisted finding creation, acceptance/completion and events. This observation does not infer live execution from a configured runtime. Expand a batch for paginated findings, with links into the same batch selection. Refresh and foreground polling remain GET-only.

The new fields are additive read contracts; no database schema, agent contract, budget, workflow definition, retry/cancellation behavior or historical replay identity changes. Generated OpenAPI/client declarations must be rebuilt from these canonical contracts.
