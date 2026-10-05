# Deployment support

Use `./dev` from the repository root for local development. It combines the root compose files
with checkout-specific state, a managed VM and verified sandbox fixtures. Source changes to the
backend take effect with `./dev reload`; web source uses Vite hot reload.

This directory contains database bootstrap SQL, collector configuration, the build-egress proxy
and [Kubernetes control-plane templates and sandbox specifications](k8s/README.md). `docker-compose.yml` and
`docker-compose.dev.yml` remain at the root as discoverable entry points.

The base compose configuration is an advanced manual path. It does not automatically reuse the
managed VM, project identity, credentials or allocated ports. Every image in both compose files
and the backend `Dockerfile` is pinned by version and digest; the Python, uv and Node versions
must equal `.mise.toml`, and `tests/development/test_dev_experience.py` checks both. The artifact
store keeps its `minio` service name but runs RustFS (S3-compatible, same ports and health
probe), because MinIO images are no longer published. Kubernetes manifests and a Pod renderer
exist; Kubernetes probe submission is not implemented.

The development overlay rotates container logs at 10 MiB with three files per service. Successful
full startup and `./dev logs [service]` save bounded snapshots under `.harness/logs/`. Operational
volumes, snapshots and artifacts are retained across `./dev stop` and `./dev stop --vm` (which also
stops this checkout's VM); do not delete them as build cache. `./dev reset` is the one explicit,
confirmed way to delete this checkout's VM, volumes, findings and generated configuration, and
`./dev gc [--delete]` lists or removes VM homes under `~/.cache/ih/` whose checkout is gone.
See [local setup](../docs/development/LOCAL_SETUP.md) and the [repository guide](../docs/development/REPOSITORY_GUIDE.md).

Temporal history and visibility use separate PostgreSQL databases, `temporal` and
`temporal_visibility`. Their independent schemas must not share a schema-version table. The
bootstrap creates both databases for a fresh volume; Temporal auto-setup creates the missing
visibility database for existing volumes. Managed smoke requires the completed demo to be
queryable through Temporal visibility, in addition to persisted API results.


Service connections can use local or hosted infrastructure without changing workflow code.
See [service environments](../docs/development/SERVICE_ENVIRONMENTS.md) for Temporal TLS/auth,
PostgreSQL TLS, AWS or S3-compatible artifact storage, hosted telemetry and environment-file examples.
The Kubernetes control-plane template leaves the Docker-backed worker disabled until its
separate executor and shared workspace are verified. No Kubernetes probe submission is added.
