# Credential broker operator runbook

This runbook describes the current opt-in broker interfaces. It does not authorize a
production rollout or a provider call. The packaged catalog is disabled, and a configuration
that merely names an OpenShell runtime is not evidence that a native executor is ready.
Measured status is recorded per run under [`docs/evidence/`](../evidence/README.md); the latest
is the [broker qualification checkpoint](../evidence/2026-10-04-broker-qualification-checkpoint/README.md).
See the [implementation evidence](../evidence/2026-10-01-broker-implementation/CREDENTIAL_BROKER_IMPLEMENTATION.md) for exact gate scope. Paid-provider calls are outside this runbook.

## 1. Pin and prepare operator-owned files

The supported initial OpenShell release is 0.1.2 at source commit
`6648bd0c290efbc41ba131ee9831ee45cd431f94`. Verified platform archive SHA-256 values and OCI
index pins are recorded in [`.dev-tools/openshell.json`](../../.dev-tools/openshell.json). For
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

For a Qwen-compatible endpoint, the existing `enable_thinking: false` option can be shared
by several per-agent routes. Copy a reviewed backend with that option, add its model-catalog
aliases, and route only the chosen agents to it. The current qualification candidate reuses
one such backend for `intake`, `probe-diagnosis`, `verdict` and `build-repair`; the other seven
agents preserve provider default reasoning. This prepared configuration requires its fresh
qualification; it does not supersede the retained failed full-run evidence. Each selected broker profile must have the exact same backend name and
thinking option. Resolve new contracts and verify fresh native readiness before calls; do
not rebind existing held requests. This is endpoint-specific operator configuration, not a
change to the packaged default Bedrock routing.

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
to exercise the real checkout Temporal service and replay of the histories that run records
(there is no pre-change baseline replay). Its native lifecycle is an explicit test-only fake
from `infosec_harness.qualification.broker.service` and cannot establish OpenShell enforcement:

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

Leases move through a persisted state machine (`creating`, `ready` or `quarantined`,
`revoked`, `sandbox_deleted`, `deleted`); a deleted lease's secret record is replaced by a
secret-free archive entry, and startup reconciliation touches only leases a previous process left
behind. Failures are classified: inconsistent input or ownership is `identity`, an unreachable
ledger, database or gateway is `unavailable`. After upgrading the controller or executor
sources, rebuild the executor image and run fresh native readiness and qualification before
admitting traffic ([specification](SPEC.md#implemented-lease-lifecycle-and-error-classification)).

Run closure is authenticated and scoped to an existing run/root. It fences the run, marks
unresolved requests failed-before-dispatch or completion-unknown according to state, revokes
native leases, and retains ledger records, root cost/allocation state, and tombstones. Local
broker execution closes the run through its scoped controller call; Temporal cleanup uses the
registered close activity when the broker workflow path is enabled. If cleanup fails, retain
the private state and reconcile using the same controller ownership. Do not manually delete
all Docker containers, mutate a global Docker context, reset the managed VM/data, remove
tombstones, or release possible spend to force cleanup.

## Explicit conservative closure of retained unknown holds

Use `scripts/broker_hold_closure.py` only as an operator with authenticated database access
and exact, independently corroborated controller/lease ownership. It has no HTTP endpoint,
model call, native lifecycle or automatic retry. Confirm every affected lease is Deleted,
native inventory is empty, the root deadline is expired, and run/operation revocation is
persisted. Gateway reachability or similar timestamps cannot establish exact completion.
Preserve a private backup of the affected complete request/root rows and source/evidence
pins before applying. An absent provider result stays absent.

Freeze a version-1 JSON manifest with `source_commit`, `evidence` (named absolute-file/SHA256
references) and `operations` (`ClosureRequest` records). Each record contains exact root and
operation IDs, expected full root SHA256/revision, all operation request IDs and full-row
SHA256s, the exact sorted unknown-request allowlist, source commit, the same named evidence
hashes, and `reason: loss_accepted`. `row_sha256` in persistence reconciliation canonically
hashes every mapped column with UTC-normalized timestamps; never hash a partial row or
publish source-bearing request payloads. One operation per root is permitted per manifest;
replan a further operation explicitly against the changed root. No discovery means consent.

```bash
HARNESS_ENV_FILE=/private/operator.env uv run python scripts/broker_hold_closure.py \
  --manifest /private/closure.json --manifest-sha256 <frozen-sha256> \
  --report .harness/reports/credential-broker/closure-dry-run.json
# After inspecting the exact dry-run result, apply the same frozen manifest:
HARNESS_ENV_FILE=/private/operator.env uv run python scripts/broker_hold_closure.py \
  --manifest /private/closure.json --manifest-sha256 <frozen-sha256> --apply \
  --report .harness/reports/credential-broker/closure-applied.json
```

The configured `HARNESS_GIT_COMMIT_SHA` must match the reviewed implementation and manifest.
Reports use fresh private paths. Source/evidence byte drift, malformed dimensions, missing
rows, changed rows, unexpired or unrevoked roots and nonterminal requests fail closed.
All operations are preflighted before writing; each root update uses a transactional revision
CAS. A later conflict stops the batch and retains which operations were already applied.
Identical repeated authorization is idempotent; changed authorization is refused.

Closure consumes the FULL operation reservation in every root dimension, without releasing
capacity or inventing usage. `closed_unknown` remains distinct from observed settlement;
workers cannot overwrite it and repeated revocation preserves it. Dispatch tombstones,
request allocations, failed historical trials and model results remain unchanged. The API/UI
reports unresolved unknown holds and conservatively closed requests separately. Invalid
audit data remains unresolved; unavailable database reads remain unavailable. The new
accounting state requires this implementation before any resumed reservation reader is used.
No schema or Temporal workflow generation changes are needed; no recorded activity is replayed
or retried to perform closure. Qualification must start from a new post-closure state snapshot.

## 5. Checks and qualification runners

Useful deterministic commands are:

```bash
uv run pytest tests/runtime/test_broker_profiles.py tests/runtime/test_broker_transport.py
uv run pytest tests/persistence/test_inference_ledger.py tests/persistence/test_broker_admission.py tests/runtime/test_broker_invocations.py
uv run pytest tests/runtime/test_broker_executor.py tests/runtime/test_openshell_controller.py
just check
just test
```

Each command's pass applies only to the cases it executed; inspect skips and reports.

Operator qualification runners live in `src/infosec_harness/qualification/broker/` and run from
a checkout. Their offline regressions are in `tests/qualification/`.

| Runner | Command |
| --- | --- |
| Mock-provider native acceptance (`native-*` proof files) | `python -m infosec_harness.qualification.broker.native mock-provider\|worker\|prove` ([deployment](../../deploy/openshell/README.md)) |
| Frozen-manifest real-provider pilot | `python -m infosec_harness.qualification.broker.pilot --manifest <file> --manifest-sha256 <sha256> [--phase ...] [--allow-inference]`; endpoint and model come only from the frozen manifest |
| One production graph trial | `scripts/broker_real_graph_check.py freeze\|execute` |
| Service fixtures | `scripts/broker_service_check.py [--temporal]` |
| Ledger concurrency and recovery | `scripts/broker_ledger_check.py` |

The
[current implementation evidence](../evidence/2026-10-01-broker-implementation/CREDENTIAL_BROKER_IMPLEMENTATION.md) distinguishes
actual PostgreSQL, native mock-provider recovery and Temporal replay checks from the
[local-provider qualification](../evidence/2026-10-01-broker-implementation/CREDENTIAL_BROKER_LIVE_PROVIDER.md). All eleven
direct agent cases and the direct production graph passed on the authorized local endpoint.
Native live compatibility failed; native live full-graph and held-out quality are not checked.
These records do not approve opt-in rollout; the packaged catalog remains disabled.

For native inference failures, fixed executor markers distinguish provider, codec and ledger
stages without exposing payloads or exceptions. The final local-provider investigation also
captured a stale policy generation from an exact owned supervisor. The generation guard closes
active streams when policy changes or quarantine is published. Preserve this boundary. Establish
the actual activation/quarantine trigger before proposing remediation; do not infer it from
elapsed time, disable the guard, retry ambiguous requests or treat model discovery as inference
reliability. Any new qualification requires fresh bounded frozen trial identities and unchanged
expected outcomes. Preserve existing uncertain reservations and reports. Qualification-only
file sinks and capture wrappers are excluded from production acceptance.
