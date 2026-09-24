# Infosec Harness v2 — Exploitability Triage Spec (DRAFT)

Status: **draft for design review** · Open decisions are marked **[Q#]** and collected in
[§12](#12-open-questions).

## 1. Purpose

Take vulnerability findings that an **external process already produced** (SAST, SCA,
pentest notes, bug bounty, etc.) and, for each one:

1. understand the target codebase (any language: Java, Python, Perl, JS/React, …),
2. work out how to build and run it (dependencies, toolchain, test runner),
3. draft a **targeted unit-test probe** for that finding,
4. execute the probe in an isolated sandbox, and
5. return one verdict: `potentially_exploitable` | `likely_not_exploitable` |
   `inconclusive`, with evidence and a priority.

The system *filters, prioritizes, and triages*. It does not find new vulnerabilities,
write fixes, or touch production.

### Non-goals (v2.0)
- Discovering new vulnerabilities or running full scanners.
- Remediation or patch generation.
- Exploiting deployed or networked environments. Probes run only against code in a sandbox.
- A custom agent framework. See §3.

## 2. Guiding principles

1. **Use PydanticAI instead of building our own.** Agents, tools, skills, output
   validation, usage limits, fallback models, test models, evals, graphs, and durable
   execution all come from `pydantic-ai`, `pydantic-ai-harness`, `pydantic-graph`, and
   `pydantic-evals`. We write custom code only where these packages do nothing
   (sandbox, finding intake, persistence schema).
2. **Keep each agent small.** Each agent is a *prompt + skills + tools + typed output*,
   defined declaratively, has one job, and has its own eval dataset.
3. **Keep code deterministic where possible.** Parsing, building, executing, scoring, and
   persistence are plain Temporal activities. LLMs make judgment calls only.
4. **Measure every change.** Every run records the model, prompt hash, skill-set hash,
   toolset hash, and git SHA with its accuracy, cost, and latency, so any change can be
   compared against a baseline.
5. **Run locally first.** `docker compose up` runs the whole system. The same images
   later deploy to Kubernetes.

## 3. Framework capabilities we will rely on

Verified against PyPI on 2026-09-24: `pydantic-ai 2.49.0`, `pydantic-ai-harness 0.34.0`,
`pydantic-evals 2.49.0`, `pydantic-graph 2.49.0`, `temporalio 1.33.0`.

| Need | Existing capability | Custom code? |
|---|---|---|
| Agent definition, typed output, retries/validation | `pydantic_ai.Agent(output_type=…, deps_type=…)`, output validators, `ModelRetry` | No |
| Skills (progressive disclosure) | `pydantic_ai_harness.Skills` (agentskills.io `SKILL.md` format, loaded via `load_capability`) | Skill content only |
| Read-only code navigation | `pydantic_ai_harness.FileSystem` (path-safe read/list/search) | Configuration only |
| Command execution | `pydantic_ai_harness.Shell` (allow/deny lists, timeouts), **run inside the sandbox** (§7) | Sandbox routing (small) |
| Large tool output | `pydantic_ai_harness.tool_output_limits` | No |
| Prompt-injection defence (repo content is untrusted) | `pydantic_ai_harness.prompt_injection_defender`, `guardrails` | Configuration only |
| Budgets | `UsageLimits` per run + `pydantic_ai_harness.spend` | No |
| Model portability/fallback | `pydantic_ai` model strings, `FallbackModel` | No |
| Multi-step orchestration | `pydantic_graph` (`GraphBuilder` / nodes) | Graph definition |
| Durable execution | `pydantic_ai.durable_exec.temporal` (`TemporalAgent`, `PydanticAIPlugin`, `PydanticAIWorkflow`) | Workflow + activities |
| Deterministic unit tests of agents | `TestModel`, `FunctionModel`, `Agent.override` | No |
| Evaluation | `pydantic_evals` `Dataset`/`Case`, `EqualsExpected`, `IsInstance`, `HasMatchingSpan`, `ToolCorrectness`, `TrajectoryMatch`, `MaxToolCalls`, `ConfusionMatrixEvaluator`, `PrecisionRecallEvaluator`, `LLMJudge` (last resort) | Datasets + a few domain evaluators |
| Cost | `RunUsage` + `genai-prices` | No |
| Tracing/latency | OpenTelemetry instrumentation built into pydantic-ai (Logfire or any OTLP backend) **[Q4]** | No |

## 4. Architecture overview

```
               ┌──────────────┐   submit   ┌─────────────────────────────────────────┐
  findings ───►│ API / CLI    │──────────► │ Temporal: TriageBatchWorkflow           │
  (SARIF/JSON) └──────────────┘            │   └─ child: FindingTriageWorkflow × N   │
                     │                     │        runs pydantic_graph of agents    │
                     ▼                     └──────────┬───────────────┬──────────────┘
               ┌──────────────┐    activities         │               │  TemporalAgent
               │  Postgres    │◄──────────────────────┘               ▼  model/tool activities
               │ runs/findings│                              ┌──────────────────┐
               │ evals/costs  │                              │ LLM providers    │
               └──────────────┘                              └──────────────────┘
                     ▲                  ┌───────────────────────────────────────┐
                     └──────────────────│ Sandbox runner (per-target container, │
                        artifacts       │ no egress after dependency install)   │
                        (blob store)    └───────────────────────────────────────┘
```

Workflows are split in two levels:
- `RepoPreparationWorkflow`: runs **once per repo@revision** and is cached. It covers
  recon, the environment spec, the image build, and a smoke test. Many findings in one
  repo share one prepared environment.
- `FindingTriageWorkflow`: runs **once per finding**. It covers context, the probe plan,
  the probe, execution, repair, the verdict, and the priority.

## 5. Agent graph

Legend: 🤖 = LLM agent (`TemporalAgent`), ⚙️ = deterministic activity.

### 5.1 Repo preparation (per repo@revision)

| # | Node | Type | Single duty | Tools / skills | Output type |
|---|---|---|---|---|---|
| P0 | `CheckoutRepo` | ⚙️ | Clone or mount the repo at its revision; compute a content hash | — | `RepoSnapshot` |
| P1 | `DetectStack` | ⚙️ | Fingerprint languages, manifests, and lockfiles using heuristics (e.g. `github-linguist`-style extension counts plus manifest detection) | — | `StackFingerprint` |
| P2 | `ReconAgent` | 🤖 | Describe the application: components, entry points, frameworks, test layout | FileSystem (ro), Skills: `lang-*` | `RepoProfile` |
| P3 | `EnvPlannerAgent` | 🤖 | Produce a build spec: base image, system packages, dependency install, test command | FileSystem (ro), Skills: `build-*` (maven, gradle, pip/uv/poetry, cpanm, npm/pnpm/yarn…) | `EnvironmentSpec` |
| P4 | `BuildEnvironment` | ⚙️ | Render a Dockerfile from `EnvironmentSpec` and build it | — | `BuildResult` |
| P5 | `BuildRepairAgent` | 🤖 | On a build failure, read the logs and patch the `EnvironmentSpec` (bounded loop, max *k*) **[Q6]** | Shell (in sandbox), Skills: `build-*` | `EnvironmentSpec` |
| P6 | `SmokeTest` | ⚙️ | Run a trivial test in the built image to prove the test harness works | — | `SmokeResult` |

If preparation fails after *k* repair attempts, every finding in the repo is marked
`inconclusive` with reason `environment_unbuildable`. This is still useful triage signal.

### 5.2 Finding triage (per finding)

| # | Node | Type | Single duty | Tools / skills | Output type |
|---|---|---|---|---|---|
| F0 | `NormalizeFinding` | ⚙️ | Convert an external finding into the canonical `Finding` (CWE, location, flow, severity, source tool) **[Q1]** | — | `Finding` |
| F1 | `PreFilter` | ⚙️ | Apply cheap deterministic filters: file is missing, code is test-only or vendored, a duplicate fingerprint exists, the rule is in a denylist | — | `continue` \| early verdict |
| F2 | `ContextAgent` | 🤖 | Gather the code slice: source→sink path, the called functions, how untrusted input reaches the sink, sanitizers seen | FileSystem (ro), Skills: `cwe-*`, `lang-*` | `FindingContext` |
| F3 | `ProbePlannerAgent` | 🤖 | Decide *what* a test must show and define an **oracle**: the observable signal that means exploitable (exception, canary file, tainted value reaching sink, output match) | Skills: `cwe-*` (per-CWE probe patterns and oracles) | `ProbePlan` |
| F4 | `ProbeAuthorAgent` | 🤖 | Write the test in the repo's own test framework (JUnit, pytest, Test::More, Jest/RTL…) | FileSystem (ro), Skills: `test-*` per framework | `ProbeSource` |
| F5 | `ExecuteProbe` | ⚙️ | Run the probe in the prepared image with no network, a time limit, and resource caps; capture exit code, stdout/stderr, and oracle signals | — | `ProbeExecution` |
| F6 | `ProbeDiagnosisAgent` | 🤖 | Classify the result: *probe defect* (compile error, wrong import) vs *valid negative* vs *valid positive* vs *environment issue* | Skills: `test-*` | `ProbeDiagnosis` |
| F7 | `ProbeRepairAgent` | 🤖 | Only on a probe defect: fix the probe, then return to F5 (bounded, max *m*) | FileSystem (ro), Skills: `test-*` | `ProbeSource` |
| F8 | `VerdictAgent` | 🤖 | Weigh the finding, context, plan, and execution evidence and output the 3-way verdict, confidence, rationale, and evidence references | none (reasons only over the evidence it is given) | `Verdict` |
| F9 | `Prioritize` | ⚙️ | Deterministic score: verdict × severity × reachability × confidence | — | `TriageResult` |

The graph encodes the control flow (F5→F6→F7→F5 loop, early exits from F1, the jump to
`inconclusive` when preparation failed). Each 🤖 node runs **exactly one agent** with one
typed output. The graph routes on that typed output, never on free text.

### 5.3 Verdict semantics (deterministic contract)
- `potentially_exploitable`: the oracle fired in a **valid** probe execution (F6 = valid
  positive).
- `likely_not_exploitable`: the probe executed validly, the oracle did not fire, **and**
  the plan's preconditions were exercised (e.g. the tainted value reached the call site),
  **or** `ContextAgent` shows no reachable path with cited code.
- `inconclusive`: the environment could not be built, the probe could not be repaired
  within budget, the budget ran out, or the evidence conflicts.

`VerdictAgent` proposes a verdict. A deterministic **validator** (a pydantic-ai output
validator that raises `ModelRetry`) rejects verdicts that break these rules. For example,
`potentially_exploitable` is rejected when the oracle never fired.

## 6. Agent anatomy (declarative)

Each agent is a folder:

```
agents/probe_author/
  agent.py        # ~20 lines: Agent(model, output_type, deps_type, instructions, capabilities)
  instructions.md # system prompt (hashed & versioned)
  evals/
    dataset.yaml  # pydantic_evals Dataset (cases + evaluators)
skills/
  test-pytest/SKILL.md  test-junit5/SKILL.md  test-perl-test-more/SKILL.md  test-jest-rtl/SKILL.md
  cwe-89-sqli/SKILL.md  cwe-78-cmdi/SKILL.md  cwe-22-path/SKILL.md  cwe-502-deser/SKILL.md …
  build-maven/SKILL.md  build-uv/SKILL.md  build-cpanm/SKILL.md  build-npm/SKILL.md …
```

An agent's configuration is `(model, instructions hash, skill set hash, toolset
signature)`. It is recorded on every invocation and can be overridden per run for
experiments. For example: `--override probe_author.model=anthropic:claude-sonnet-5
--override probe_author.skills+=test-junit5-v2`.

## 7. Sandbox & execution

Probes execute untrusted, LLM-generated code against untrusted repository code, so this
is the main safety boundary.

- **Local:** one container per prepared image. Network is allowed only during the
  dependency-install build stage and set to `none` at probe time. The container runs as a
  non-root user, with a read-only root filesystem except the probe workdir, cpu/mem/pids
  limits, and a wall-clock timeout. **[Q2]** decides the isolation technology.
- **Kubernetes:** each `ExecuteProbe` becomes a short-lived Job/Pod in a dedicated
  namespace with a default-deny NetworkPolicy, `runtimeClassName` (gVisor/Kata) per
  **[Q2]**, and no service-account token.
- Agents never get a host shell. The `Shell` capability, where used (P5 only), runs its
  commands **inside** the target sandbox through a small adapter, which is our only
  custom tool plumbing. Most agents only get read-only `FileSystem`.
- Images and repo snapshots are content-addressed and cached, keyed by
  `repo_hash + EnvironmentSpec hash`.

## 8. Durable execution (Temporal)

- One Temporal worker deployment hosts both workflows and activities, plus a separate
  task queue for **sandbox activities** so they can be scaled or isolated independently.
- Every agent is wrapped once at import: `TemporalAgent(agent, name=...)`. Model requests
  and tool calls become activities with retry policies automatically, and workflow code
  stays deterministic.
- The pydantic-graph run executes **inside** the workflow. Nodes call `TemporalAgent.run`
  or `workflow.execute_activity`. We do not use pydantic-graph's own persistence, because
  Temporal's history is the source of truth for resumption. **[Q3]**
- Idempotency: workflow ID = `triage:{finding_fingerprint}:{repo_revision}:{config_hash}`,
  so re-submitting the same finding with the same configuration is de-duplicated.
- Human-in-the-loop hooks use Temporal signals/updates, e.g. approve probe execution or
  override a verdict. **[Q8]**

## 9. Persistence (Postgres)

The Temporal server uses its own Postgres database/schema. The application schema
(SQLAlchemy 2 + Alembic) is:

| Table | Purpose |
|---|---|
| `repos`, `repo_snapshots` | Repo URL, revision, content hash, `StackFingerprint`, `RepoProfile` |
| `environments` | `EnvironmentSpec`, build status, image digest, build logs (artifact ref) |
| `batches`, `findings` | External finding (raw + normalized), source tool, fingerprint |
| `triage_runs` | One per (finding × config). Temporal workflow ID, status, verdict, confidence, priority, timings |
| `agent_invocations` | One per agent call: agent name, model, instructions/skills/tools hashes, input/output (JSONB), tokens, cost USD, latency, retries, trace ID |
| `probe_executions` | Probe source ref, exit code, oracle signals, duration, sandbox profile |
| `artifacts` | Content-addressed blobs (probe files, logs, Dockerfiles). Bytes live on a local volume or in S3/MinIO **[Q5]** |
| `eval_experiments`, `eval_case_results` | See §10 |

Pydantic models are the single source of truth. JSONB columns store `model_dump()`
output, and SQL columns hold what we filter and aggregate on.

## 10. Evaluation strategy

### 10.1 Per-agent evals (the unit)
Each agent has a `pydantic_evals.Dataset` whose inputs are the agent's typed inputs,
frozen as fixtures, so agents can be evaluated **in isolation** without running the graph.

| Agent | Primary deterministic evaluators |
|---|---|
| ReconAgent | Set precision/recall on languages, frameworks, and entry points vs labelled truth |
| EnvPlannerAgent | **Executes**: does the image build and does the smoke test pass? (binary, deterministic) |
| ContextAgent | Recall of labelled source/sink/sanitizer line ranges |
| ProbePlannerAgent | Oracle type matches the CWE's allowed oracle set, and the schema is valid |
| ProbeAuthorAgent | **Executes**: the probe compiles/runs, and on labelled-vulnerable cases the oracle fires |
| ProbeDiagnosisAgent | `EqualsExpected` on the defect/negative/positive/env label |
| VerdictAgent | `EqualsExpected` on the verdict; `ConfusionMatrixEvaluator` across the dataset |
| All | `MaxToolCalls`, `MaxDuration`, `ToolCorrectness`/`TrajectoryMatch` where the expected tool use is known; cost and tokens from `RunUsage` |

`LLMJudge` is used only for rationale quality, and is always reported separately from
the deterministic scores.

### 10.2 End-to-end evals
The full graph runs on a labelled corpus of (repo, finding, ground-truth verdict).
Headline metrics: per-class precision/recall, the **false-negative rate on truly
exploitable findings** (the costliest error), the `inconclusive` rate, $/finding, and
p50/p95 latency/finding. **[Q7]** decides the corpus.

### 10.3 Experiment tracking
- An **experiment** = dataset version × config (models, instructions hashes, skills
  hashes, tool signatures, git SHA) × repetitions (to measure LLM variance).
- Results go to `eval_experiments` / `eval_case_results`. pydantic-evals' report diff
  (`report.print(baseline=...)`) is used for the terminal, and SQL views drive dashboards.
- CLI: `harness eval run --agent probe_author --config configs/x.yaml --repeat 3` and
  `harness eval compare <exp_a> <exp_b>`. The compare output shows accuracy, cost, and
  latency deltas with confidence intervals.
- CI runs the fast per-agent evals with **recorded model responses** (replayed through
  `FunctionModel`) for deterministic regression checks. Live-model evals run on demand
  or nightly.

## 11. Deployment

- **Local:** `docker compose up` starts `postgres`, `temporal` (auto-setup) +
  `temporal-ui`, `worker`, `api` (FastAPI), an OTel collector/trace UI **[Q4]**, the
  sandbox runtime (§7), and optionally `minio`.
- **Kubernetes (later):** Helm chart or Kustomize (the repo already has Kustomize) with
  Temporal via its official Helm chart or Temporal Cloud, managed Postgres, workers as a
  Deployment, and sandbox Jobs in an isolated namespace. KEDA or Temporal worker
  autoscaling is out of scope for v2.0.
- The project uses `uv`, Python 3.12, ruff, and pytest. `just` recipes stay.

### Proposed repo layout
```
src/infosec_harness/
  domain/           # Pydantic models: Finding, RepoProfile, EnvironmentSpec, ProbePlan, Verdict…
  intake/           # finding adapters (SARIF, generic JSON, …)
  agents/<name>/    # agent.py + instructions.md + evals/dataset.yaml
  graph/            # pydantic_graph definitions for prep + triage
  workflows/        # Temporal workflows + activities + worker entrypoint
  sandbox/          # docker / k8s runner behind one interface
  persistence/      # SQLAlchemy models, Alembic migrations, repositories
  evals/            # shared evaluators, experiment runner, compare CLI
  api/ cli/
skills/             # SKILL.md libraries (lang-*, build-*, test-*, cwe-*)
deploy/compose/  deploy/k8s/
eval-corpus/        # labelled cases (or git submodules / fetch scripts)
```

### Phased delivery (proposal)
1. **Skeleton:** compose stack, domain models, Postgres schema, a Temporal workflow with
   stub agents (`TestModel`), and a CLI submit/report path.
2. **Python-only vertical slice:** all agents real for pytest + 3 CWEs, with per-agent
   eval datasets and a baseline experiment.
3. **Evals and experiment comparison tooling:** the compare CLI, recorded-response CI
   evals, and the E2E corpus v1.
4. **Language breadth:** Java (Maven/Gradle + JUnit), JS/React (npm + Jest/RTL), and Perl
   (cpanm + Test::More) as **skills plus eval cases**, with no new agents.
5. **K8s manifests and hardened sandbox runtime.**

## 12. Open questions
Each question is asked with multiple-choice options. Answers will be folded back into
this document.

- **Q1** Input formats for pre-identified findings.
- **Q2** Sandbox isolation technology (local and k8s).
- **Q3** How pydantic-graph and Temporal divide responsibility.
- **Q4** Observability/tracing backend.
- **Q5** Artifact storage.
- **Q6** Repair budgets and build strategy.
- **Q7** Ground-truth evaluation corpus.
- **Q8** Human-in-the-loop points.
- **Q9** Model providers.
- **Q10** What to do with the existing v1 code.
- **Q11** Primary interface (CLI / API / UI).
