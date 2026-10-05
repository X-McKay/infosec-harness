# Local and hosted service connection support

## Scope and contracts

The user requested local development/testing and Kubernetes workloads connected to hosted
Temporal, PostgreSQL and other relevant services, explicitly excluding state/data migration.
This change adds process/deployment configuration, not migration tooling or a new scheduler.

The shared Temporal connection used by API/CLI/worker supports verified TLS, optional private
CA/server name, API-key environment or mounted-file credentials, and mTLS. Settings reject
plaintext authentication and incomplete certificate pairs. An explicit missing environment
file or mounted key fails without local fallback. Database runtime and existing schema commands
share a verified PostgreSQL asyncpg SSL context; offline SQLite remains unchanged. Percent-encoded
URLs now survive Alembic configuration interpolation. No schema revision is added.

Artifact selection supports explicit AWS S3 with default endpoints/credential discovery,
session credentials, CA bundles and addressing style, while preserving local auto selection.
Bucket creation only follows a missing-bucket response when enabled; forbidden, server and
network errors do not create a bucket or select filesystem fallback. Hosted templates disable
creation. Optional OTLP headers and client TLS require HTTPS; prompt/completion exclusion remains.

The Kubernetes operator template deploys a restricted API and a separately configured worker,
using Secrets for credentials, read-only certificate mounts and a ClusterIP API. Worker replicas
start at zero pending an actual qualified Docker/runsc executor, TLS Docker credentials and
an identical daemon-visible shared workspace. The API readiness endpoint is an application
probe, not evidence of Temporal, sandbox or full graph readiness. These manifests do not install
Temporal/PostgreSQL/S3 or implement Kubernetes probe Job submission.

## Durable behavior and provenance

No workflow type, input/payload, routing decision, activity retry policy, ledger fence, request
identity, broker wire protocol, artifact digest or schema changes. Connection options remain
outside workflow history. Existing replay/recovery expectations are unchanged; reconnecting
never grants permission to redispatch an uncertain inference request. Environment-file settings
and pooled clients remain cached per process, so restart to choose another environment. API,
worker and controller must agree on application database/catalog and relevant service settings.

The broker wire version and semantic agent/system behavior versions remain unchanged. Deployment
images/build provenance must record the new source revision; opt-in broker immutable image/full
contracts retain their normal enforcement. This is connector capability and infrastructure
configuration, not a claim that an existing workflow can move between clusters.

## Checks

| Gate | Result |
| --- | --- |
| Focused connector/artifact/schema/telemetry/deployment regressions | passed: 54 tests |
| Full deterministic suite | passed: 2,322 tests; 40 skips; 861 warnings; 79.50 seconds |
| Canonical lint/compile/agent validation | passed |
| Generated artifacts and development-skill drift | passed |
| Independent TLS/auth/local compatibility and deployment-boundary review | passed |
| Kubernetes YAML/static trust-boundary tests | passed |
| Kubernetes kustomize/server-side validation and actual deployment | not_checked: no cluster or kubectl supplied |
| Actual hosted Temporal/PostgreSQL/S3/OTLP connections/workload identity | not_checked: no hosted instances or credentials supplied |
| Hosted worker actual runsc/build-egress/full production graph | not_checked: executor must be qualified in its environment |
| Native Kubernetes probe Job runner | not_applicable: renderer only, no runner added |
| UI checks | not_applicable: no UI change |
| New state/data migration tests | not_applicable: explicitly out of scope |

The earlier native qualification failure and thirteen retained uncertain requests remain
unchanged; this connection support does not resolve the pending native Temporal transport
failure. See [native rerun evidence](../2026-10-01-broker-implementation/CREDENTIAL_BROKER_NATIVE_RERUN.md).

## Operator references

- [Service environment settings and local/hosted examples](../../development/SERVICE_ENVIRONMENTS.md)
- [Kubernetes prerequisites and deployment template](../../../deploy/k8s/README.md)

Before enabling hosted live workers, verify actual TLS/auth, database schema/access, content-
addressed artifact roundtrip, Temporal workflow/replay, and the executor's real isolation,
build-egress and shared-path behavior. No hosted services or cluster resources were modified
for this change.
