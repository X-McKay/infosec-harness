# Proposal 1: Bounded Evidence Pipeline

## Summary

Build a local, single-operator Python CLI that executes fixed security workflows and
uses one bounded agent loop only for investigation. It supports OpenAI, Anthropic, and
future providers through thin adapters, runs target code only in an offline ephemeral
strong-isolation sandbox, and produces evidence-backed JSON/SARIF plus a human-readable
report.

This is the recommended starting point. It has the fewest moving parts, makes policy
and cost behavior inspectable, and directly tests whether the models improve the
existing AppSec workflow.

## Intended deployment

- One analyst or a small AppSec team.
- Local workstation or dedicated single-tenant worker.
- Tens of repository scans or hundreds to low thousands of imported findings per
  week.
- Read-only discovery and triage by default; validation in a disposable writable
  gVisor/Kata/microVM sandbox.
- No unattended public-facing service and no automatic external writes.

## Architecture

```text
CLI / just recipe
      |
authorization + config validation
      |
manual/read-only context adapters -> immutable SecurityContextBundle
      |
Python state machine ---------------- provider adapter -> OpenAI / Anthropic
      |                                      |
      |                                usage + policy errors
      |
typed tool broker -> read-only analysis sandbox -> target snapshot
      |
approved ValidationPlan -> separate agent guest -> sealed synthetic target range
      |
SQLite run metadata + content-addressed artifacts + JSONL audit
      |
JSON/SARIF/Markdown report -> human review

Separate process/command:
Inspect evaluation runner -> same provider adapters and agent policy
```

No message queue, API server, external database, workflow engine, or LLM gateway is
required. Concurrency is bounded `asyncio` within one controller process.

## Components

### Domain core

Pydantic models define `Authorization`, `Task`, `Budget`, `SecurityContextBundle`,
`Finding`, `Evidence`, `Disposition`, `ThreatModel`, `ValidationPlan`, `ToolCall`, and
`RunRecord`. JSON Schema versions are explicit and migrations are tested. Provider
output cannot bypass validation.

### Provider adapters

Use the official `openai` and `anthropic` Python SDKs. Each adapter:

- converts the normalized request into the provider-native API;
- advertises supported features and rejects unsupported combinations;
- implements provider-specific retry classification, caching, reasoning, and batch
  options without leaking SDK objects into the domain core;
- normalizes token usage, stop reasons, tool calls, request IDs, policy failures, and
  actual model identifiers;
- supports a fake/replay backend for deterministic tests.

A third provider is one new adapter plus contract tests, not a change to workflows.

### Runtime

Implement the explicit state machine in ordinary Python. The investigation loop can
request at most the tools in the current stage and terminates on submission, policy
block, budget, time, repeated/no-progress calls, or a configured number of
no-new-candidate passes.

Use fixed pipelines:

- `review`: threat model, deterministic inventory, candidate discovery, validation,
  adjudication, report.
- `diff-review`: diff map, targeted context, validation, report.
- `triage`: SARIF ingest, dedupe, contextual adjudication, optional validation,
  report.
- `threat-model`: system evidence extraction, boundary/asset model, threat
  elicitation, coverage check, human review.

The pilot does not need an enterprise graph product. Source-specific read-only
adapters normalize a few approved catalog, deployment, API, and business-invariant
facts into a pinned bundle. The model can request a typed fact or evidence excerpt but
cannot query enterprise APIs or choose connector credentials.

### Tools

Start with repository search/read/tree, SARIF import, selected static analyzers,
build/test by configured ID, and finding submission. Do not expose an MCP client or
arbitrary network tool in the pilot. Add a restricted sandbox shell only for workflows
whose held-out evaluations show it is necessary.

After the pilot, a `CodexSecurityScannerAdapter` may ingest sealed Codex Security scan
artifacts through the same finding/evidence schema. It runs only in the harness's
scrubbed disposable worker and never substitutes for the controller's provider,
authorization, coverage, or sandbox policy.

Dynamic validation uses registered action and oracle IDs, not a general scanner or
shell. An immutable plan binds the finding, rules of engagement, context/target
digests, synthetic fixtures, allowed actions, budgets, expected observation, health
abort conditions, evidence, approvals, and teardown.

### Storage

SQLite stores run/task state, budgets, decisions, normalized usage, and artifact
indexes. Blobs live under a content-addressed artifact directory. JSONL audit events
make runs inspectable even if the database is damaged. Encrypt the volume when target
code or findings are sensitive. Never store provider keys or hidden reasoning.

### Evaluation

Install Inspect AI in a development/evaluation dependency group. Implement an Inspect
solver that invokes the same runtime policy and a small set of local tasks before
adding public cyber suites. Evaluation containers and hidden graders remain separate
from production runtime modules.

### Gym

Implement a small `SecurityEnvironment` core and Gymnasium wrapper in a development
group. Version 1 records/replays trajectories and evaluates controller policies; it
does not update model weights. See [Evaluation and gym](../evaluation-and-gym.md).

## Toolchain

### `mise`

Commit a `mise.toml` that pins a tested Python 3.12 patch release and exact versions of
`uv`, `just`, and `prek`. `mise` owns developer tool versions; it does not own secrets.
Do not put provider keys in committed `mise` configuration.

### `uv`

Use a `pyproject.toml` and committed `uv.lock`. Separate groups keep the runtime small:

- base: CLI, Pydantic, provider SDKs, structured logging;
- sandbox: isolation backend helpers for rootless OCI and stronger execution;
- scanners: optional language-specific integrations;
- eval: Inspect, Gymnasium, statistical/reporting tools;
- dev: pytest, Hypothesis, Ruff, type checker, security checks.

### `justfile`

Recommended recipes:

```text
just setup
just check
just test
just test-integration
just sandbox-self-test
just scan TARGET REVISION
just triage SARIF TARGET REVISION
just threat-model TARGET REVISION
just eval-smoke PROVIDER MODEL
just eval-suite SUITE PROVIDER MODEL
just gym-record SUITE PROVIDER MODEL
just gym-replay RUN_ID
just cost-report RUN_ID
```

Recipes are the canonical command entry points for developers and CI. They call
package CLIs; business logic does not live in the `justfile`.

### `prek`

Use a pre-commit-compatible configuration with hook repositories frozen to immutable
commit SHAs. Begin with formatting/linting, type checks, secret detection, dependency
audit, unsafe YAML checks, and repository-specific tests. Use `prek update` with a
cooldown and review dependency diffs rather than following new tags automatically.

## Configuration

Use non-secret TOML/YAML configuration for named policies and environment variables or
an OS secret broker for credentials. A run config selects capabilities, not provider
marketing tiers:

```yaml
models:
  routine_triage:
    provider: anthropic
    model: exact-model-id
    max_output_tokens: 2000
  deep_review:
    provider: openai
    model: exact-model-id
    reasoning: medium
  critical_verifier:
    provider: anthropic
    model: exact-model-id

budgets:
  repository_review:
    max_cost_usd: 25
    max_model_calls: 40
    max_tool_calls: 160
    max_wall_seconds: 3600
    max_parallel: 3
```

Dollar caps use a dated price catalog and a conservative preflight estimate. Token,
call, and time caps remain authoritative if a current price is unknown. Actual vendor
usage is reconciled after the run.

## Security posture

The pilot is single-tenant but not trusted-target. It implements all baseline controls
from the [reference architecture](../reference-architecture.md): signed or approved
scope, rootless container, no ambient secrets, no container socket, network denied,
resource caps, typed tools, path canonicalization, untrusted-output handling, and
human approval for consequential transitions.

Run discovery against a read-only target snapshot. Rootless OCI is sufficient only for
tasks that do not execute target-controlled code. Validation gets a new writable copy
under gVisor, Kata, or a microVM, not the discovery agent's accumulated filesystem. If
that backend is unavailable, validation stays disabled rather than falling back to a
plain container. A verifier starts with a fresh model context and receives the claim
and evidence, not the discoverer's persuasive transcript.

For remote providers, the runner checks data-classification policy against the current
endpoint/feature retention profile. A provider feature that is not approved for the
target is rejected before any request.

External context and dynamic validation follow
[External context and safe issue validation](../context-and-safe-validation.md).
Connector workers use separate read-only identities and expose only normalized facts.
Active tests run in a production-free, two-sided range: the worker cannot reach
internal systems, while target compromise cannot reach the worker's provider channel,
controller, verifier, or evidence store. `Not_reproduced` cannot produce a
false-positive disposition without positive counter-evidence and adequate environment
and oracle fidelity.

## Cost strategy

1. Scanner import, fingerprints, deduplication, repository maps, and changed-file
   selection are deterministic and cached.
2. Routine triage receives the scanner rule, trace, and a targeted source slice.
3. Discovery uses a strong model but limits surfaces and stops after measured novelty
   exhaustion.
4. Verification occurs only for actionable candidates.
5. A second provider is used for high-impact or uncertain decisions, not every item.
6. Backlog work may use provider batch APIs only when its data classification and
   retention requirements allow it.

The run summary shows spend by stage, model, finding, and outcome. Promotion decisions
use validated findings/dollar, analyst time saved, and time from validated issue to
verified remediation, not aggregate token savings.

## Evaluation gates

Before scanning sensitive repositories, require:

- provider contract tests against fake and live low-risk fixtures;
- sandbox tests proving no network, host home, engine socket, metadata endpoint, or
  provider secret is reachable;
- adversarial repository fixtures for prompt injection, symlink/path traversal,
  archive bombs, output floods, ANSI escapes, poisoned SARIF, and malicious build
  scripts;
- a balanced internal triage set with confirmed findings and realistic false-positive
  traps;
- at least one temporal vulnerability-discovery set not used during prompt iteration;
- reproducibility and evidence-integrity checks;
- stale/conflicting/poisoned external-context cases and connector access tests;
- environment-equivalence, oracle-sensitivity, target-range egress, kill-switch, and
  outcome-classification tests;
- AppSec-approved false-dismissal and abstention behavior.

## Delivery sequence

### Phase 0: evaluation contract

Define authorization, context/fact, finding/evidence, and validation-plan schemas,
budgets, reviewer labels, and the first 20-50 internal eval cases before writing the
agent loop. Capture the current human baseline.

### Phase 1: safe triage vertical slice

Implement provider/fake adapters, SARIF ingest, read/search tools, offline no-exec container,
routine triage, evidence report, audit log, and contract/adversarial tests. This yields
useful value without exploit execution.

Manually create a context bundle for each pilot system and measure which external
facts change threat priorities or finding dispositions. Automate only the first few
high-value read-only sources after this establishes the schema.

### Phase 2: bounded discovery and validation

Add context-backed threat modeling, surface planning, candidate discovery, a signed
target manifest, separate agent guest and synthetic target range under
gVisor/Kata/microVM isolation, deterministic out-of-band oracles, strong-model
escalation, and report export.

### Phase 3: evaluation and replay

Add Inspect integration, the internal suite, selected public tasks, multi-trial
statistics, trajectory record/replay, and the Gymnasium wrapper.

### Phase 4: measured hardening

Tune prompts, retrieval, model routing, and budgets only against development cases;
run held-out release gates; complete privacy/security review; document operator
runbooks and incident handling.

For one senior Python engineer with part-time AppSec review, a useful triage pilot is
roughly a 2-4 engineer-week scope; discovery, hardened sandboxing, and meaningful
evaluation typically make the complete pilot a 6-10 engineer-week scope. These are
planning ranges, not commitments, and exclude creation of a large labeled corpus or
enterprise deployment work.

## Acceptance criteria

- OpenAI and Anthropic can execute the same workflow and return the same domain schema.
- A third fake provider proves adapter isolation in tests.
- Every reported item resolves to an immutable target revision and stored evidence.
- Every deployment/business premise resolves to a pinned context fact, explicit
  assumption, contradiction, or coverage gap.
- Unsupported claims become `inconclusive`, not findings or false-positive closures.
- Active validation cannot start without a valid plan, target manifest, synthetic
  fixtures, containment self-test, health abort, and external oracle.
- `not_reproduced`, `invalidated`, environment mismatch, policy block, and
  infrastructure error remain distinct.
- All external writes and scope/network changes are blocked or explicitly approved.
- Budgets terminate work deterministically, including retry storms and stalled loops.
- The same task is replayable with recorded tool results.
- Eval reports separate model failure, policy refusal, budget stop, timeout, grader
  failure, and infrastructure error.
- The held-out suite beats the existing workflow on agreed quality and analyst-effort
  metrics at an acceptable cost.

## Advantages

- Small auditable codebase and dependency surface.
- Lowest fixed infrastructure cost.
- Direct support for provider-specific capabilities.
- Fastest route to representative internal measurements.
- Core schemas, policy, evals, and sandbox APIs migrate to Proposal 2.

## Limitations

- Single-controller throughput and local sandbox capacity.
- SQLite and local artifacts require disciplined backups and retention management.
- Team-wide access control, quotas, and scheduling remain manual.
- Native provider adapters require maintenance when APIs change.
- Rootless OCI isolation is not the strongest boundary for hostile exploit research.

## Exit signals

Move to Proposal 2 when concurrent teams need centralized credentials/quotas, jobs
must survive workstation failure, audit/retention policy must be enforced centrally,
or a shared sandbox pool is cheaper than per-operator environments. Move directly to
Proposal 3 only for a genuine evaluation/training program with high-risk targets or
GPU-scale open-model work.
