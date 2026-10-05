# Credential broker

The credential broker is an opt-in model transport: harness workers send typed model requests to
an authenticated controller, which runs them in a minimal OpenShell-managed executor that alone
holds provider credentials. It is disabled by default (`src/infosec_harness/config/credential-broker.yaml`
is a disabled reference catalog), direct transport is never an automatic fallback, and no
production rollout is authorized.

| Document | Read it for |
| --- | --- |
| [SPEC.md](SPEC.md) | Security boundary, request architecture, endpoint policy, failure and recovery contract, lease lifecycle, provenance, acceptance cases |
| [PROTOCOL.md](PROTOCOL.md) | The frozen `ih-inference-v1` wire protocol, admission, ledger channel and native policy identity |
| [RUNBOOK.md](RUNBOOK.md) | Operator files, contract inspection, starting controller and worker, rotation, recovery, conservative closure of unknown holds, qualification runners |
| [OpenShell deployment](../../deploy/openshell/README.md) | Building the executor image, native acceptance and the real-provider pilot |

Code lives in `src/infosec_harness/inference/`, one subpackage per role (`wire`, `catalog`,
`executor`, `worker`, `controller`, `native`; see the
[repository guide](../development/REPOSITORY_GUIDE.md#where-to-change-things)); qualification
runners in `src/infosec_harness/qualification/broker/`. Phase names (P0 to P8) and every
measurement are dated records under [`docs/evidence/`](../evidence/README.md): the
[implementation plan and records](../evidence/2026-10-01-broker-implementation/README.md),
[OpenShell feasibility](../evidence/2026-10-01-openshell-feasibility/README.md), the
[full evaluation](../evidence/2026-10-02-broker-full-eval/README.md) and the latest
[qualification checkpoint](../evidence/2026-10-04-broker-qualification-checkpoint/README.md).
