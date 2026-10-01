# Deployment support

Use `./dev` from the repository root for local development. It combines the root compose files
with checkout-specific state, a managed VM and verified sandbox fixtures. Source changes to the
backend take effect with `./dev reload`; web source uses Vite hot reload.

This directory contains database bootstrap SQL, collector configuration, the build-egress proxy
and [Kubernetes sandbox specifications](k8s/README.md). `docker-compose.yml` and
`docker-compose.dev.yml` remain at the root as discoverable entry points.

The base compose configuration is an advanced manual path. It does not automatically reuse the
managed VM, project identity, credentials or allocated ports. Kubernetes manifests and a Pod
renderer exist; Kubernetes probe submission is not implemented.

The development overlay rotates container logs at 10 MiB with three files per service. Successful
full startup and `./dev logs [service]` save bounded snapshots under `.harness/logs/`. Operational
volumes, snapshots and artifacts are retained across `./dev stop`; do not delete them as build cache.
See [local setup](../docs/development/LOCAL_SETUP.md) and the [repository guide](../docs/development/REPOSITORY_GUIDE.md).

Temporal history and visibility use separate PostgreSQL databases, `temporal` and
`temporal_visibility`. Their independent schemas must not share a schema-version table. The
bootstrap creates both databases for a fresh volume; Temporal auto-setup creates the missing
visibility database for existing volumes. Managed smoke requires the completed demo to be
queryable through Temporal visibility, in addition to persisted API results. No volume reset
is required for this correction.
