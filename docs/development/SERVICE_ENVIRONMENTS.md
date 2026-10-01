# Local and hosted service environments

The same API, CLI and worker use environment configuration for service connections. Local
`./dev` remains a checkout-owned, pinned stack with real sandbox checks; it does not switch
itself to hosted infrastructure. Use separate process/deployment configuration for hosted
services. No state or data migration tooling is introduced.

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
| Artifacts | Auto filesystem, or MinIO endpoint | Explicit `HARNESS_ARTIFACT_BACKEND=s3`; AWS default endpoint/credential chain or an HTTPS S3-compatible endpoint |
| Telemetry | Optional local HTTP collector | HTTPS collector with optional authenticated headers, CA and mTLS |
| Models/broker | Existing model/catalog configuration | Existing configured endpoints and HTTPS controller catalog; no location-dependent fallback |
| Sandbox executor | Managed verified runsc/build-egress | Independently qualified Docker/runsc executor; Kubernetes worker placement does not replace it |

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
No hosted endpoints or Kubernetes cluster were modified during these tests.
