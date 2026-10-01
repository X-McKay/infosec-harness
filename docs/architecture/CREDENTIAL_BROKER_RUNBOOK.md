# Credential broker operator runbook

This runbook describes the current opt-in broker interfaces. It does not authorize a
production rollout or a provider call. The packaged catalog is disabled, and a configuration
that merely names an OpenShell runtime is not evidence that a native executor is ready.
Current reported status: PostgreSQL ledger, real TLS service, real Temporal service recovery
with a mock native adapter, registered local/eval parity and installed-wheel checks passed.
Production-native integration/recovery and P7 provider/held-out evaluation remain `not_checked`.
See the [implementation evidence](../validation/CREDENTIAL_BROKER_IMPLEMENTATION.md) for exact gate scope. Paid-provider calls are outside this runbook.

## 1. Pin and prepare operator-owned files

The supported initial OpenShell release is 0.1.2 at source commit
`6648bd0c290efbc41ba131ee9831ee45cd431f94`. Verified platform archive SHA-256 values and OCI
index pins are recorded in [`.dev-tools/openshell.json](../../.dev-tools/openshell.json). For
example, select the CLI archive for the host platform with:

```bash
python scripts/openshell_artifacts.py cli-linux-x64
```

The artifact helper downloads only the selected manifest entry, verifies its SHA-256, and
atomically places it beneath `.harness/openshell/artifacts/`. It does not extract archives,
install a global binary, start a gateway, or deploy images. The native adapter verifies the
configured CLI binary digest before each CLI operation. Use an approved, controlled unpacking
step to place the executable at the absolute path in the native deployment file. Pin workload
and supervisor images by immutable digest; an OCI index pin or artifact manifest entry alone
does not establish runtime readiness.

Keep three operator-owned files separate:

- `models.yaml` selects the backend, concrete model mapping, fixed `/v1` provider endpoint,
  and reviewed prices. For brokered routing set the chosen backend's `transport: brokered`
  and `kind: openai_compatible`. Do not set `api_key_env`, `aws_profile`, or `region` on that
  backend. `BackendConfig` rejects direct credential fields for brokered transport.
- `credential-broker.yaml` enables the broker, maps every registered agent to an approved
  profile, and defines positive finite root/per-agent request, input/output token, cost, and
  time limits. The catalog must explicitly cover `intake`, `recon`, `env-planner`,
  `build-repair`, `partial-build`, `context`, `probe-planner`, `probe-author`,
  `probe-diagnosis`, `probe-repair`, and `verdict`. Each profile binds the backend name and
  endpoint, native provider/profile references, ledger origin/profile, immutable executor
  and supervisor image digests, effective approved policy, and fixed message-adaptation
  settings. Driver is `native`, inspection is empty, and provider retries are zero.
- `native-deployment.yaml` configures the controller's OpenShell CLI path/digest, dedicated
  gateway/workspace and Docker socket, private configuration and TLS directories, owner-only
  lease directory, controller-to-gateway mTLS files, and native specs keyed by the full
  contract digest. Each spec corroborates the catalog policy, provider and ledger profile
  export digests, provider resource version, credential revision, and token ceilings.

The checked-in [`credential-broker.yaml`](../../src/infosec_harness/config/credential-broker.yaml)
is a disabled reference catalog with all eleven mappings. Copy it to an operator-managed
location and fill only reviewed values. The approved policy must be the fully resolved
effective OpenShell policy, including provider-composed permissions. The shared policy
identity removes only generated `_provider_` network-map labels and their redundant matching
`name` field; it retains every permission, default, authored label, and rule. The adapter also
checks the live policy, profile exports, resource version, attachment, lease labels, images,
and process confinement before considering a lease ready.

Every configured brokered model needs explicit reviewed input/output price ceilings in
`models.yaml`; unknown prices fail admission. Do not copy provider keys into any YAML file,
workflow input, worker environment, root configuration, request, log, or artifact. `provider_env`
is a name resolved inside the native provider path, not a value. The worker/controller HMAC
key is likewise referenced by environment-variable name (`hmac_env`) and supplied to both
processes by the deployment's secret manager. Do not pass the controller's native config or
provider environment wholesale to the worker.

## 2. Inspect the resolved contract and migrate the database

Set `HARNESS_MODELS_CONFIG` and `HARNESS_BROKER_CONFIG` to the operator-managed model and
broker files. Before enabling traffic, inspect the secret-free resolved contracts:

```bash
uv run python -m infosec_harness.inference.deployment --print-contracts
```

The output reports each agent's contract and digest. Confirm only intentionally brokered
agents show `transport: brokered`; check profile, endpoint, policy digest, image pins, model,
effective settings, output floor, and retry setting against approved change records. The
deployment factory uses these same contracts as native-spec keys.

Apply the additive database migration against the intended broker database before starting
the controller:

```bash
uv run harness migrate
uv run alembic current
```

The current migration head is `0005`, adding the durable `inference_requests` ledger table.
Do not use `harness init-db` against an existing deployment database. To print SQL for DBA
review instead of applying the migration, use `uv run alembic upgrade head --sql`.

The isolated PostgreSQL qualification command is:

```bash
uv run python scripts/broker_ledger_check.py --env-file <operator-postgres-env-file> --host <postgres-host>
```

The ledger command creates a uniquely named temporary database, runs transaction tests with
provider dispatches fixed at zero, drops only that database, and writes a sanitized report
under `.harness/reports/credential-broker/`. Keep the database environment file private.

A separate service qualification uses real HTTPS processes and PostgreSQL; add `--temporal`
to exercise the real checkout Temporal service and historical replay. Its native lifecycle is
an explicit test-only shim and cannot establish OpenShell enforcement:

```bash
uv run python scripts/broker_service_check.py --env-file <operator-postgres-env-file> --temporal
```

The service command also uses a uniquely named temporary database and performs scoped cleanup.
Its counted provider requests go only to a local mock HTTPS provider. Review the sanitized
report for the exact service, replay and cleanup outcomes.

## 3. Start separate controller and worker processes

The controller process needs the broker model catalog, native deployment file, database
access, worker/controller HMAC key, server certificate/key, and worker client CA. Its native
config and provider-management authority must remain controller-only. Start it with the
required TLS and factory arguments. Supply `HARNESS_DATABASE_URL` for the controller database
and have the secret manager inject the variable named by the catalog's `hmac_env`; neither
value belongs in the YAML file or command line:

```bash
HARNESS_MODELS_CONFIG=<operator-models-yaml> \
HARNESS_BROKER_CONFIG=<operator-broker-yaml> \
HARNESS_BROKER_NATIVE_CONFIG=<operator-native-deployment-yaml> \
uv run python -m infosec_harness.inference.controller \
  --factory infosec_harness.inference.deployment:controller_factory \
  --host <controller-bind-address> --port <controller-port> \
  --cert <controller-server-certificate> --key <controller-server-private-key> \
  --client-ca <worker-client-ca>
```

The worker receives only the model/broker catalog, controller HMAC reference material, and
its controller TLS CA/client certificate/key. It must not receive `HARNESS_BROKER_NATIVE_CONFIG`,
native Docker access, or provider credentials. Configure the task queue on both the Temporal
workflow starter/API and this worker. Choose a new dedicated queue, for example
`<broker-queue-v1>`:

```bash
HARNESS_MODELS_CONFIG=<operator-models-yaml> \
HARNESS_BROKER_CONFIG=<operator-broker-yaml> \
HARNESS_MODEL_MODE=live HARNESS_TASK_QUEUE=<broker-queue-v1> \
uv run harness worker
```

Do not route brokered workflows to the existing `triage` queue. The worker intentionally
refuses live brokered configuration on that queue so old direct workers can drain without
sharing a queue with the new broker behavior. Keep existing direct workers on their old
configuration until their outstanding work has drained; configure new workflow starters and
broker workers together on the new queue. Never change historical workflow configuration in
place to reinterpret recorded work as brokered.

The controller listens with TLS and can require worker client certificates. It separately
uses its configured gateway client certificate/key to reach the native HTTPS gateway. The
worker authenticates `/v1/invocations`, `/v1/infer`, `/v1/results`, and `/v1/runs/close` with
the controller HMAC channel. The executor accepts only signed `/v1/infer` requests; its
ledger credentials are scoped to `/v1/ledger/claim` and `/v1/ledger/complete`. No worker or
executor receives database authority or OpenShell administration authority.

## 4. Reconciliation, rotation, recovery, and cleanup

The controller lazily creates one executor lease per run and full contract digest. It verifies
the lease's owner labels, phase, exact effective policy, provider profiles and resource
version, attachments, immutable images, and observed confinement before dispatch. A CLI
success message by itself is not readiness. Controller restart reloads lease records from the
configured owner-only directory; before reusing a matching lease, it rechecks native resources.
It must not adopt or delete resources by name similarity. Preserve the `0700` directory and its
`0600` records across restart. This is operational recovery state, not a shareable evidence
artifact.

If a native create operation succeeds but the controller dies before persisting its returned
resource ID, v1 cannot automatically prove ownership for that resource. Preserve private state,
fence the run, and reconcile against operator gateway inventory using the complete owner labels
and creation evidence. Do not adopt or delete by name. Closure remains unacknowledged until
all resources are confirmed absent; partial detach/delete failures can be retried through the
same controller. This is a documented manual recovery boundary.

For credential rotation, update the native provider through the approved operator secret
process, increment its observed resource version and the profile's `credential_revision`,
then start a fresh controller process with the revised native configuration. The next lease
for that run is created with the new revision; the adapter revokes the old lease, detaches its
provider, waits for sandbox/container removal, and deletes its lease-scoped ledger provider.
Rotation does not change the behavior contract merely because generated provider policy labels
contain new resource identifiers. A changed permission, endpoint, profile, image, model setting,
or adaptation does change contract identity and requires new review.

After an uncertain worker acknowledgement, identical retries keep the logical request ID.
An expired binding may only query authenticated `/v1/results` for the exact retained request;
the endpoint returns a committed result or an explicit missing/pending/unknown/expired
disposition and does not provision, admit, claim, or send. `completion_unknown` is not
automatically retried as a fresh request. Replacement requests for unresolved completions are
unsupported in this version; preserve the reservation and escalate through the reviewed
recovery process.

Run closure is authenticated and scoped to an existing run/root. It fences the run, marks
unresolved requests failed-before-dispatch or completion-unknown according to state, revokes
native leases, and retains ledger records, root cost/allocation state, and tombstones. Local
broker execution closes the run through its scoped controller call; Temporal cleanup uses the
registered close activity when the broker workflow path is enabled. If cleanup fails, retain
the private state and reconcile using the same controller ownership. Do not manually delete
all Docker containers, mutate a global Docker context, reset the managed VM/data, remove
tombstones, or release possible spend to force cleanup.

## 5. Checks and current gate status

Useful deterministic commands are:

```bash
uv run pytest tests/test_broker_profiles.py tests/test_broker_transport.py
uv run pytest tests/test_inference_ledger.py tests/test_broker_admission.py tests/test_broker_invocations.py
uv run pytest tests/test_broker_executor.py tests/test_openshell_controller.py
just check
just test
```

Each command's pass applies only to the cases it executed; inspect skips and reports. Current
lead-reported PostgreSQL ledger and deterministic mock/unit gates are `passed`. Production
native integration, production Temporal replay/recovery, and P7 bounded provider/held-out
evaluation are `not_checked` unless a separate reviewed evidence record establishes them. G0
feasibility evidence concerns a bounded test prototype only. It does not approve production
model routing, real-provider spend, or an opt-in rollout. There is no manual provider request
command in this runbook; P7 requires its own approved model, explicit spend limit, frozen test
set, and independent evidence review.
