# Documentation

Start with [local setup](development/LOCAL_SETUP.md) and the
[repository guide](development/REPOSITORY_GUIDE.md). The [root README](../README.md) explains
the pipeline and the CLI. Each fact has one home; the table says which.

| Document | What it owns |
| --- | --- |
| [development/LOCAL_SETUP.md](development/LOCAL_SETUP.md) | `./dev` profiles and commands, live model configuration, migrations, troubleshooting |
| [development/REPOSITORY_GUIDE.md](development/REPOSITORY_GUIDE.md) | Module map, sources of truth, generated files, local output locations, directory conventions |
| [development/SERVICE_ENVIRONMENTS.md](development/SERVICE_ENVIRONMENTS.md) | Hosted Temporal, PostgreSQL, S3 and telemetry settings; API exposure; deploying a new execution generation |
| [architecture/TRIAGE_SYSTEM.md](architecture/TRIAGE_SYSTEM.md) | Agent roles, topology, durable execution, prompt construction, termination and limits |
| [architecture/PLAYBOOK_CONFORMANCE.md](architecture/PLAYBOOK_CONFORMANCE.md) | Mapping to the Agent and Multi-Agent Playbooks and the documented deviations |
| [threat-models/triage-system.md](threat-models/triage-system.md) | Trust boundaries, adversaries, runtime safety gates and the risk assessment |
| [evaluation/RELEASE_EVIDENCE.md](evaluation/RELEASE_EVIDENCE.md) | Release gates, baselines, held-out runs, and where accepted evidence is recorded |
| [evaluation/CORPUS_SOURCES.md](evaluation/CORPUS_SOURCES.md) | External corpus sources, licensing and harvested ground-truth limits |
| [operations/MODEL_ENDPOINTS.md](operations/MODEL_ENDPOINTS.md) | Connecting an OpenAI-compatible gateway, checking it, and reasoning-budget options |
| [operations/QUALIFICATION_DASHBOARD.md](operations/QUALIFICATION_DASHBOARD.md) | What the UI's Qualification and runtime-status views read and how operator receipts are verified |
| [broker/README.md](broker/README.md) | The opt-in credential broker: [specification](broker/SPEC.md), [wire protocol](broker/PROTOCOL.md) and [operator runbook](broker/RUNBOOK.md) |

Dated, point-in-time evidence (validation runs, qualification checkpoints, feasibility records
and the original design specifications) lives under [evidence/](evidence/README.md). Evidence is
not rewritten to match current code; living documents link to it.
