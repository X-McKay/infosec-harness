# Local and hosted service environments

The same API, CLI and worker use environment configuration for service connections. Local
`./dev` remains a checkout-owned, pinned stack with real sandbox checks; it does not switch
itself to hosted infrastructure. Use separate process/deployment configuration for hosted
services. There is no state or data migration tooling.

## Selecting configuration

Copy [local.env.example](../../deploy/environments/local.env.example) or
[hosted.env.example](../../deploy/environments/hosted.env.example) into a private operator
file, replace placeholders, and keep it out of Git (for example under `.harness/environments/`).
For standalone processes:

```bash
HARNESS_ENV_FILE=.harness/environments/hosted.env uv run harness migrate
HARNESS_ENV_FILE=.harness/environments/hosted.env uv run harness api
HARNESS_ENV_FILE=.harness/environments/hosted.env uv run harness worker
```

Environment variables override the selected file. Without `HARNESS_ENV_FILE`, the existing
`.env` behavior remains. An explicitly missing file fails; it never falls back to local
services. Settings and connection pools are process-scoped: restart when choosing another
environment. API, worker and optional broker controller must use the same application
PostgreSQL database, Temporal namespace/queue and artifact store. A controller does not need
Temporal credentials; workers do not need native controller/provider authority.

## Connection settings

| Service | Local | Hosted |
| --- | --- | --- |
| Temporal | Address and namespace; TLS off for the isolated local stack | Address, namespace and queue; `HARNESS_TEMPORAL_TLS=true`; API key or mounted mTLS pair |
| PostgreSQL | Existing `HARNESS_DATABASE_URL` | Same asyncpg URL plus `HARNESS_DATABASE_TLS=true`; optional CA and client certificate/key |
| Artifacts | Auto filesystem, or the managed RustFS S3 endpoint | Explicit `HARNESS_ARTIFACT_BACKEND=s3`; AWS default endpoint/credential chain or an HTTPS S3-compatible endpoint |
| Telemetry | Optional local HTTP collector | HTTPS collector with optional authenticated headers, CA and mTLS |
| Models/broker | Stub by default; an explicit gateway endpoint or Bedrock ([model endpoints](../operations/MODEL_ENDPOINTS.md)) | Explicitly configured endpoints and HTTPS controller catalog; no location-dependent fallback |
| Sandbox executor | Managed verified runsc/build-egress | Independently qualified Docker/runsc executor; Kubernetes worker placement does not replace it |
| Local repositories | `HARNESS_LOCAL_REPO_ROOTS` set by `./dev` to the eval corpus; the dev worker container approves `/app/eval-corpus` and `/app/deploy/dev-runtime/fixture` | Usually empty: only remote HTTPS repositories are accepted |
| Broker measurement | unset | `HARNESS_BROKER_OBSERVATION` points at the broker measurement JSON the Qualification view verifies; unset reports `not_checked` |

Temporal authentication uses `HARNESS_TEMPORAL_API_KEY` or
`HARNESS_TEMPORAL_API_KEY_FILE`; a missing/empty key file fails. API keys require TLS.
Custom trust and mTLS use `HARNESS_TEMPORAL_TLS_CA_FILE`,
`HARNESS_TEMPORAL_TLS_CLIENT_CERT`, `HARNESS_TEMPORAL_TLS_CLIENT_KEY`, and optional
`HARNESS_TEMPORAL_TLS_SERVER_NAME` for the server/SNI name. API/CLI and worker share this
connector and retain the PydanticAI plugin. No plaintext retry or namespace fallback exists.
See the [Temporal Python connection documentation](https://github.com/temporalio/documentation/blob/main/docs/develop/python/client/temporal-client.mdx).

Database trust uses `HARNESS_DATABASE_TLS_CA_FILE` and optional
`HARNESS_DATABASE_TLS_CLIENT_CERT`/`HARNESS_DATABASE_TLS_CLIENT_KEY`. Certificate and hostname
verification remain enabled. Runtime and existing schema commands share these settings;
SQLite remains supported for offline tests. PostgreSQL URLs must use `postgresql+asyncpg`;
percent-encode password characters. Do not append libpq-only `sslmode` query options to
asyncpg URLs; use these explicit TLS settings.

S3 supports `HARNESS_S3_BUCKET`, `HARNESS_S3_REGION`, optional `HARNESS_S3_ENDPOINT`,
`HARNESS_S3_CA_FILE` and `HARNESS_S3_ADDRESSING_STYLE` (`auto`, `path`, `virtual`). Explicit
credentials use the complete access/secret pair plus optional `HARNESS_S3_SESSION_TOKEN`.
Without those values boto3 uses its normal credential chain, including operator-configured
workload identity. Set `HARNESS_S3_CREATE_BUCKET=false` for pre-provisioned hosted buckets.
Authorization/network/server errors propagate; they do not trigger bucket creation or filesystem
fallback. Content addressing and digest verification are identical for both stores.

Authenticated telemetry uses JSON `HARNESS_OTEL_EXPORTER_OTLP_HEADERS` plus optional
`HARNESS_OTEL_EXPORTER_OTLP_CA_FILE`, `HARNESS_OTEL_EXPORTER_OTLP_CLIENT_CERT` and
`HARNESS_OTEL_EXPORTER_OTLP_CLIENT_KEY`. Headers/client authentication require HTTPS. Prompt,
completion and binary content remain excluded from instrumentation.

## API exposure

The API has no authentication of its own and sends no CORS headers (the wildcard CORS middleware
was removed, so a browser on another origin cannot call it). Serve the UI and the API
from one origin: the web image's nginx proxies `/api/` to the API, and the Vite development
server does the same. Expose the API only behind an authenticated internal gateway; the
Kubernetes template gives it a ClusterIP service and no Ingress.

`POST /api/batches` accepts `mode: temporal` (the default) or `mode: local`. Local mode runs
in-process with stub models only and is refused otherwise; real assessments always go through
Temporal. At startup the API bootstraps an empty database at the migration head and refuses a
database at any other revision: run `harness migrate` first.

## Deploying a new execution generation

Temporal workflow types and durable agent identities carry the execution generation from
`EXECUTION_GENERATION` in `src/infosec_harness/agents/registry.py` (currently `v6`:
`TriageBatch-v6`, `ComponentPreparation-v6`, `FindingTriage-v6`, and agent identities such as
`verdict-v6`). Workers register only the current generation, and histories recorded by an earlier
generation are not replayable by design. Before deploying a worker with a new generation, let
in-flight batches finish or terminate them, then resubmit any that were cut short as new
batches. Workflow ids are opaque (`batch:<batch-id>`); do not parse them.

## Kubernetes and testing

Use the [control-plane operator template](../../deploy/k8s/README.md#control-plane-with-hosted-services).
Secrets stay in Kubernetes Secrets or mounted files; the ConfigMap contains nonsecret service
addresses and flags. The worker starts at zero until Docker TLS, identical daemon-visible
workspace paths and actual sandbox/build-egress fixtures are supplied and verified.

Offline regression tests cover local defaults, explicit environment-file selection, TLS/auth
validation, shared connector arguments, actual SQLite schema initialization, S3 error handling,
and deployment trust boundaries. The full deterministic suite covers existing durable recovery
and replay. A deployment still needs actual hosted TLS/auth connections, database writes,
object roundtrip, Temporal workflow/replay, and executor qualification in its own environment.

## Checking an existing environment

Use the same environment file and mounted TLS/auth files as the service processes:

```bash
HARNESS_ENV_FILE=/absolute/path/to/hosted.env just validate-services \
  --api-url https://api.example.internal --web-url https://ui.example.internal \
  --worker-hostname actual-worker-hostname --expected-source-commit <40-character-commit>
```

This developer command checks existing services without migrations, workflow dispatch or
findings. The configured source commit and API/worker model identities must match. With no
`--worker-hostname`, queue poller availability is checked but exact worker identity remains
`not_checked`; supply the actual worker hostname for a complete readiness result. It uses
existing database and Temporal TLS/auth connectors without plaintext fallback.

Add `--model` only when an explicit inference request is wanted. Direct OpenAI-compatible
profiles permit one structured-output request; other transports/providers remain
`not_checked`. An optional `--connectivity-receipt /private/path/connectivity.json` emits the
existing UI receipt after success. See [local validation](LOCAL_SETUP.md#read-only-service-validation)
for reports, timeouts and scope. A reachable hosted service is not production qualification;
Kubernetes, hosted TLS/auth and execution gates still require evidence from that deployment.
