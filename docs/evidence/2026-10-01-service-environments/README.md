# Hosted service connection support (2026-10-01)

[`SERVICE_ENVIRONMENTS.md`](SERVICE_ENVIRONMENTS.md) records the change that let the API,
worker and CLI connect to hosted Temporal (TLS, API key or mTLS), PostgreSQL with TLS, S3 with
workload identity and authenticated telemetry, and its offline checks. It proves the settings
validation and connector arguments under deterministic tests. It does not prove a connection to
any real hosted service or a Kubernetes deployment; none was modified or exercised. The current
settings are documented in [service environments](../../development/SERVICE_ENVIRONMENTS.md).
