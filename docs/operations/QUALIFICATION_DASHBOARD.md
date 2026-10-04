# Qualification dashboard operations

The Qualification page reads `GET /api/qualification` and `GET /api/runtime-status`. It displays selected evidence for all 11 agent semantic components, their measured source, case counts, dependency assessment and freshness. A passed component matrix does not establish a fresh full 118 run, hosted/Kubernetes qualification or system/network reliability. Retained failures remain failures; the dashboard does not rescore reports or release accounting holds.

See [component qualification](../evaluation/COMPONENT_QUALIFICATION.md) for the reviewed ledger and [the current checkpoint](../validation/CREDENTIAL_BROKER_QUALIFICATION_CURRENT.md) for the contributing measurements and retained failures.

## Evidence and invalidation

The shared qualification assessor verifies record identities, evidence file hashes and each component's declared dependency inventory. Current file dependencies are hashed from actual bytes beneath the source checkout; a commit label does not substitute for those hashes. Inventories cover the relevant agent, shared runtime, model/configuration, dataset and grader dependencies rather than unrelated documentation or timestamps.

Unchanged dependencies permit reuse of a complete measured cohort. A reviewed equivalence must bind the exact scope, before/after dependency digests, reviewer and retained evidence. A changed or missing dependency makes the affected component require retesting or a new review. A stale equivalence cannot approve a new candidate, and a review cannot promote failed or unchecked evidence. Existing report/cardinality validators remain the scoring authority.

The page uses `fresh` for passed evidence measured at the candidate commit, `reused` for verified passed evidence from another commit, `stale` for changed dependencies, and `unavailable` when verified evidence is unavailable. Case counts come from the pinned completion witness or retained cardinality artifact. The overall component status is passed only when all 11 selected components pass. `as_of` is the API assessment time, not the time a model or sandbox was exercised.

## Operator bundle

Set `HARNESS_QUALIFICATION_BUNDLE` to an operator-owned JSON file. Its exact top-level keys are:

| Key | Required value |
| --- | --- |
| `version` | Integer `1` |
| `ledger` | Pinned reference to the reviewed version-1 ledger |
| `current` | Pinned reference to the candidate dependency inventory |
| `reviews` | Pinned reference to the equivalence reviews |
| `selection` | Agent-to-record-ID mapping containing exactly all 11 registered agents |
| `broker_observation` | Pinned reference to the retained broker observation |

Every pinned reference has exactly `file` and `sha256` keys: an API-readable file path and its lowercase SHA256 digest. Each selected record must identify the matching agent and `agent_semantics` scope. `current` contains `qualification_candidate_commit` and `components`; its file dependencies must resolve to the actual deployment source files. The API can display `HARNESS_GIT_COMMIT_SHA` as the candidate label, but still checks dependency bytes.

Do not copy private evidence into the frontend or embed developer workstation paths in deployment configuration. The bundle and its referenced operator artifacts are not packaged application resources. Local deployments must configure paths accessible to their API process. Hosted deployments must mount the bundle, evidence and required source/configuration inventories read-only at their own deployment paths. Keep credential/key files outside public qualification inventories. Retained configuration identities remain private provenance.

Missing configuration, missing files, drift, malformed references or incomplete selections produce `not_checked`; they do not fall back to fabricated results. Qualification evidence must be prepared and reviewed before deployment. The dashboard has no evidence-generation, qualification-run or promotion action.

## Broker observation

Configure the real broker catalog through `HARNESS_BROKER_CONFIG`. Configuration alone establishes only `configured: true`. Without a valid observation the broker remains `not_checked`; an unconfigured deployment defaults to `configured: false` and `not_checked`.

The version-1 broker observation has exactly `version`, `checked_at`, `valid_until`, `status`, `catalog_sha256`, `dependencies` and `evidence`. Its `evidence` contains pinned `owner`, `health` and `readiness` references. These trusted operator receipts must agree on source and owner, controller identity, loaded inference-module bytes, configuration identities and all 11 native contract readiness observations. The readiness receipt must attest that its exact owned test leases were deleted and native inventory returned to zero. The catalog and relevant files are checked against their retained hashes.

`HARNESS_QUALIFICATION_OBSERVATION_MAX_AGE_SECONDS` defaults to `3600` and permits values from `30` through `86400`. Observation timestamps must be timezone-aware, ordered and within this configured lifetime. Expired observations are labeled stale and report `not_checked`; increasing the limit does not create a new measurement.

For a valid observation, runtime status also makes a bounded credential-free request to the configured controller: TLS verification uses its configured CA, redirects and environment proxies are disabled, and unsigned `POST /v1/infer` with `{}` must return exactly `401` with the auth rejection. The probe is cached for up to 30 seconds and makes no model call. It confirms the live rejection channel; it is not a fresh native sandbox/readiness test and does not renew the retained observation. A failed live channel check reports failed; invalid or unavailable evidence reports `not_checked`.

The runtime response exposes environment, model mode, assessment transport, API source label, database backend name, Temporal TLS/plaintext mode and bounded broker metadata. It does not expose credentials, connection strings, catalog paths, private receipt paths, raw exceptions or model payloads. Environment and mode labels describe configuration, not qualification evidence.

`unresolved_requests` counts persisted `completion_unknown` requests in the configured database. An unavailable count is displayed as unavailable, not zero. These requests retain their accounting holds. Refreshing the dashboard does not resend, retry, reconcile or release them; recovery requires the existing explicit operator process and exact request provenance.

## Operational UI behavior

The production client always requests `population=operational` for batches, runs, metrics and evaluations, including their detail views. URL/search population overrides cannot select demo or legacy data. Selected batch finding/status/verdict counts cover only matching runs; the shared batch budget remains batch-wide. Existing stored data is retained, and unscoped API callers preserve their compatibility behavior.

The client never seeds demo findings, sample results or fallback fixture data. Production APIs must use the operational store: controlled qualification/graph fixture databases remain separate validation sources and must not be connected as the production finding store. Population filtering uses persisted provenance; it cannot determine whether an incorrectly tagged historical record was fabricated. Set `HARNESS_MODEL_MODE=live` and the actual model/broker configuration for operational deployments; explicit stub/offline development and isolated test profiles remain test tools. An empty operational database displays an honest empty state. Evaluations offer manual refresh and foreground polling every 10 seconds, including when the list is empty; active evaluation detail also polls. Qualification and runtime observations refresh every 30 seconds, and Qualification's Refresh button refreshes both. Background polling is disabled. Fetch errors are visible and do not manufacture successful observations.

The persistent environment/mode indicator and Settings runtime panel use the same real runtime response. They do not hardcode a local environment or infer readiness from a configured provider/runtime name.

## Contract and recovery impact

These endpoints and views are read-only projections, plus the bounded unsigned admission check. They do not alter agent behavior, output contracts, budgets, thresholds, Temporal activity identities or workflow histories. No durable generation/version bump or workflow recovery migration is introduced by the dashboard. Its public contracts and generated clients must remain synchronized through the repository's generated-artifact checks.
