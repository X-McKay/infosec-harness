# Documentation

Start with [local setup](development/LOCAL_SETUP.md) and the [repository guide](development/REPOSITORY_GUIDE.md).
The [root README](../README.md) explains the pipeline and common commands.

| Topic | Read | Purpose |
| --- | --- | --- |
| Local development | [LOCAL_SETUP.md](development/LOCAL_SETUP.md) | Managed launcher, offline work, migrations and troubleshooting |
| Service environments | [SERVICE_ENVIRONMENTS.md](development/SERVICE_ENVIRONMENTS.md) | Local configuration and Kubernetes workloads with hosted services |
| Organization | [REPOSITORY_GUIDE.md](development/REPOSITORY_GUIDE.md) | Modules, generated sources, local outputs and directory conventions |
| Architecture | [SPEC.md](architecture/SPEC.md) | Design and decision history; use current code for implemented behavior |
| Evolution contracts | [HARNESS_EVOLUTION_SPEC.md](architecture/HARNESS_EVOLUTION_SPEC.md) | Durable behavior, provenance, accounting and acceptance requirements |
| Credential brokering | [Design specification](CREDENTIAL_BROKER_SPEC.md), [implementation and testing plan](architecture/CREDENTIAL_BROKER_IMPLEMENTATION_PLAN.md), [protocol](architecture/CREDENTIAL_BROKER_PROTOCOL.md), [operator runbook](architecture/CREDENTIAL_BROKER_RUNBOOK.md), [evidence](validation/CREDENTIAL_BROKER_IMPLEMENTATION.md), [full live evaluation](validation/CREDENTIAL_BROKER_FULL_EVAL.md) | OpenShell boundaries, per-agent profiles, delegated work, recovery and acceptance gates |
| Safety | [threat-models/triage-system.md](threat-models/triage-system.md) | Threats and runtime boundaries |
| Governance | [PLAYBOOK_CONFORMANCE.md](architecture/PLAYBOOK_CONFORMANCE.md) | Playbook mapping and documented deviations |
| Evaluation fixtures | [CORPUS_SOURCES.md](evaluation/CORPUS_SOURCES.md), [corpus README](../eval-corpus/README.md) | Fixture sources and paired ground truth |
| Acceptance evidence | [IMPLEMENTATION_VALIDATION.md](validation/IMPLEMENTATION_VALIDATION.md) | Implemented checks and remaining acceptance gaps |
| Historical measurements | [LIVE_VALIDATION.md](validation/LIVE_VALIDATION.md) | Prior endpoint observations; not current runtime acceptance |
| Cleanup review | [validation/repository-cleanup.md](validation/repository-cleanup.md) | Scope, compatibility, checks and recovery assessment |
| Reorganization review | [repository-reorganization.md](validation/repository-reorganization.md) | Delivered moves, compatibility, provenance and check evidence |
| Agent quality | [plan](evaluation/AGENT_QUALITY_PLAN.md), [review](evaluation/AGENT_QUALITY_REVIEW.md), [fixes](validation/AGENT_QUALITY_GATE_FIXES.md) | Current qualification work and historical evidence |
| Development handoff | [HANDOFF.md](development/HANDOFF.md) | Latest imported qualification checkpoint; historical runs retain their original provenance |
| Local release validation | [local-release-validation.md](validation/local-release-validation.md) | Combined develop validation, managed runtime and push evidence |

`risk-assessments/` contains generated agent assessments. `validation/` contains deliberately
reviewed evidence; transient local reports belong under `.harness/reports/`.
