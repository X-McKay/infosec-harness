# Deployment

There is no production deployment target. The local control plane is three loopback processes
that `./dev` starts on the host: the pinned Temporal CLI dev server (`temporal server
start-dev`, persisted to the SQLite file `.harness/temporal/temporal.db`, with its bundled UI),
`harness api` and the Vite UI. There is no application database, object store, credential
broker, container image for the control plane or second agent runtime. The managed VM
(`deploy/dev-runtime/lima.yaml`) hosts native OpenShell and the Docker daemon that builds
trusted workload images; see [OpenShell provisioning](openshell/README.md).

The trusted worker runs separately with `harness worker` and an explicit OpenShell runtime
configuration. Its source snapshots and command receipts require durable storage; do not launch
replicas with independent copies of that state. Temporal replay alone cannot recover an
unrecorded external effect.

Every port binds loopback. Remote deployment would require authenticated ingress, a production
Temporal service with TLS/authentication, mTLS to the OpenShell gateway, native provider
configuration and durable worker state. Secrets belong in operator-managed files or native
provider configuration. The local stack is not a production deployment.

The `investigate-v11` task queue is incompatible with v10 and older workflows. Drain older
queues before replacement. `harness qualify` proves actual runtime behavior; API health
only checks Temporal connectivity. Run live evaluation separately against the chosen model.

## Migrating from the compose stack

Earlier checkouts ran Temporal on PostgreSQL in a compose project inside the VM. That
PostgreSQL volume holds the v11 histories recorded so far, including the five preserved
`live-eval-v11-201cc101da4a` histories that every candidate replays. The new dev server starts
with an empty database and cannot read it, so export the histories you need while the old
stack is still running. Do this once, in the main checkout, with no `./dev worker` or
`./dev eval` running and no v11 workflow you still need to finish.

1. Check out the new code without running `./dev` (that would rewrite `dev.env`, which still
   names the compose project and builder). Keep a private copy of the old values and put the
   managed tools on `PATH`:

   ```bash
   git fetch origin && git checkout <commit-with-this-change>
   command cp -p .harness/dev.env .harness/dev.env.compose   # mode 0600; holds the DB password
   set -a; source .harness/dev.env.compose; set +a
   export HARNESS_TEMPORAL_ADDRESS="127.0.0.1:$HARNESS_TEMPORAL_PORT"
   eval "$(./dev env)"
   ```

2. Inspect what the old server still retains. The compose image's default namespace
   retention is likely 24 hours (the compose file never set one), so closed histories older
   than that may already be gone; nothing here can recover them. Running workflows are listed
   separately so you can drain them first:

   ```bash
   temporal operator namespace describe --namespace default --address "$HARNESS_TEMPORAL_ADDRESS"
   temporal workflow list --address "$HARNESS_TEMPORAL_ADDRESS" \
     --query "WorkflowId STARTS_WITH 'investigate-v11-' AND ExecutionStatus = 'Running'"
   ```

3. Export every retained v11 history (at least the five replay histories) to
   `.harness/histories/<run-id>.json`. Export is read-only and never overwrites a file:

   ```bash
   temporal workflow list --address "$HARNESS_TEMPORAL_ADDRESS" --limit 100000 -o jsonl \
     --query "WorkflowId STARTS_WITH 'investigate-v11-'" |
     python3 -c 'import json, sys; [print(json.loads(l)["execution"]["workflowId"]) for l in sys.stdin if l.strip()]' |
     sort -u >.harness/histories-v11.txt
   while read -r run_id; do
     uv run --locked harness export-history "$run_id" </dev/null || echo "NOT exported: $run_id" >&2
   done <.harness/histories-v11.txt
   ```

   For each of the five replay histories, confirm the exported file is the replayed history:
   `uv run --locked harness replay <run-id>` must pass, and its `history_sha256` must equal
   `shasum -a 256 .harness/histories/<run-id>.json`.

4. Remove the old image builder. It is attached to the compose build-egress network, which
   the next step removes; `--keep-state` keeps its BuildKit state volume:

   ```bash
   .harness/bin/docker buildx rm --keep-state "$HARNESS_BUILDX_BUILDER"
   ```

5. Stop the compose project by its old name. Without `--volumes`, its PostgreSQL volume
   (`${COMPOSE_PROJECT_NAME}_pgdata`) and every other volume stay in the VM:

   ```bash
   .harness/bin/docker compose --project-name "$COMPOSE_PROJECT_NAME" down --remove-orphans
   .harness/bin/docker volume ls --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME"
   ```

   If this Compose version asks for a configuration file, give it the old one and its values
   (the docker shim runs Compose inside the VM, so host variables do not reach it):
   `git show 0d583dc:docker-compose.yml >.harness/compose-legacy.yml`, then add
   `-f .harness/compose-legacy.yml --env-file .harness/dev.env.compose` before
   `--project-name`.

6. Start the new stack. `./dev` keeps the checkout's ports, drops the retired keys from
   `dev.env`, starts Temporal, the API and the UI, checks readiness and requalifies OpenShell
   (with the runtime JSON named by `HARNESS_OPENSHELL_CONFIG` when set, else at
   `.harness/openshell/private/native-config.json` or `.harness/openshell/runtime.json`):

   ```bash
   ./dev
   ./dev status
   ```

   If Temporal reports its port in use, the VM's port forward for the old container has not
   been released yet; wait a few seconds and rerun `./dev`.

Removing the compose networks changes the original VM daemon's iptables rules.
`scripts/openshell_guest.py stop` compares the shared firewall with the baseline recorded when
the dedicated OpenShell daemon started, so after step 5 it refuses with "shared firewall
changed since startup; operator review required". That refusal is the intended fail-closed
signal. To keep the baseline meaningful, stop the dedicated daemon (it must have no live
workloads) before step 5 and start it again after, then run `./dev qualify`; use the
`openshell_guest.py stop` and `start` commands from
[OpenShell provisioning](openshell/README.md#prepare-the-checkout-owned-runtime).

The exported files are the durable record; `harness replay RUN_ID` reads only the live server.
To replay a history that exists only in the old volume, temporarily start the legacy Temporal
on another free loopback port from the old compose file (step 5) and a copy of the old values,
replay against it, then stop it again without `--volumes`:

```bash
git show 0d583dc:docker-compose.yml >.harness/compose-legacy.yml
(umask 077 && sed 's/^HARNESS_TEMPORAL_PORT=.*/HARNESS_TEMPORAL_PORT=<free-port>/' \
  .harness/dev.env.compose >.harness/dev.env.legacy)
legacy() {
  .harness/bin/docker compose -f .harness/compose-legacy.yml --env-file .harness/dev.env.legacy \
    --project-name "$COMPOSE_PROJECT_NAME" "$@"
}
legacy up -d postgres temporal
HARNESS_TEMPORAL_ADDRESS=127.0.0.1:<free-port> uv run --locked harness replay <run-id>
legacy down
```

Existing VMs keep the gVisor runtime their template installed as the original daemon's
default; image builds still work there. A VM created from the current template uses plain
`runc`. Delete `.harness/dev.env.compose` once nothing needs the old stack.
