# Infosec Harness v2 — Exploitability Triage Spec (DRAFT)

Status: **draft for design review**. Decisions made in design review are marked **[D#]** and
recorded in [§12](#12-decisions-log). Remaining open items are in [§13](#13-open-questions).

## 1. Purpose

Take vulnerability findings that an **external process already produced** and delivered as
generic JSON, Azure DevOps work items, or free-text reports **[D1]**, and, for each one:

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
| Inference backends | `BedrockConverseModel` + `BedrockProvider(profile_name=…, region_name=…)` for AWS Bedrock with SSO; `OpenAIChatModel` + `OpenAIProvider(base_url=…, api_key=…)` for any OpenAI-spec endpoint; `FallbackModel` **[D9]** | A ~50-line model factory (§6.1) |
| Multi-step orchestration | `pydantic_graph` (`GraphBuilder` / nodes) | Graph definition |
| Durable execution | `pydantic_ai.durable_exec.temporal` (`TemporalAgent`, `PydanticAIPlugin`, `PydanticAIWorkflow`) | Workflow + activities |
| Deterministic unit tests of agents | `TestModel`, `FunctionModel`, `Agent.override` | No |
| Evaluation | `pydantic_evals` `Dataset`/`Case`, `EqualsExpected`, `IsInstance`, `HasMatchingSpan`, `ToolCorrectness`, `TrajectoryMatch`, `MaxToolCalls`, `ConfusionMatrixEvaluator`, `PrecisionRecallEvaluator`, `LLMJudge` (last resort) | Datasets + a few domain evaluators |
| Cost | `RunUsage` + `genai-prices` | No |
| Tracing/latency | OpenTelemetry instrumentation built into pydantic-ai, exported over OTLP to a self-hosted collector and trace UI **[D4]** | No |

## 4. Architecture overview

```
               ┌──────────────┐   submit   ┌─────────────────────────────────────────┐
  findings ───►│ API/CLI/ADO  │──────────► │ Temporal: TriageBatchWorkflow           │
  (JSON/ADO/   └──────────────┘            │   └─ child: FindingTriageWorkflow × N   │
   text)             │                     │        runs pydantic_graph of agents    │
                     ▼                     └──────────┬───────────────┬──────────────┘
               ┌──────────────┐    activities         │               │  TemporalAgent
               │  Postgres    │◄──────────────────────┘               ▼  model/tool activities
               │ runs/findings│                              ┌──────────────────┐
               │ evals/costs  │                              │ LLM providers    │
               └──────────────┘                              └──────────────────┘
                     ▲                  ┌───────────────────────────────────────┐
                     └──────────────────│ Sandbox runner (per-target container, │
                        artifacts       │ gVisor, no egress at probe time)      │
                        (MinIO/S3)      └───────────────────────────────────────┘
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
| P5 | `BuildRepairAgent` | 🤖 | On a build failure, read the logs and patch the `EnvironmentSpec`. The loop is aggressive but has hard caps **[D6]** | Shell (in sandbox), Skills: `build-*` | `EnvironmentSpec` |
| P5b | `PartialBuildAgent` | 🤖 | Fallback when a full build fails: find the **smallest buildable unit** that contains the finding (a single module, a subproject, or the target package with unrelated dependencies stubbed) and produce a reduced `EnvironmentSpec` | FileSystem (ro), Shell (in sandbox), Skills: `build-*`, `partial-build` | `EnvironmentSpec` (scope=`partial`) |
| P6 | `SmokeTest` | ⚙️ | Run a trivial test in the built image to prove the test harness works | — | `SmokeResult` |

**Build effort [D6] (aggressive).** The defaults below are configuration, and evals tune them:

- Full build: up to 6 `BuildRepairAgent` iterations.
- Then up to 4 `PartialBuildAgent` / repair iterations per finding-bearing module.
- A per-repo spend cap (`pydantic_ai_harness.spend`) and a wall-clock cap apply to the
  whole preparation.
- Environments record `scope = full | partial`. A partial environment is cached per
  (repo, module) and reused by every finding in that module. Verdicts from a partial
  environment are tagged, so evals can compare accuracy on partial vs full environments.

If both paths are exhausted, the repo's findings are marked `inconclusive` with reason
`environment_unbuildable`. This is still useful triage signal.

### 5.2 Finding triage (per finding)

| # | Node | Type | Single duty | Tools / skills | Output type |
|---|---|---|---|---|---|
| F0a | `IntakeAdapter` | ⚙️ | Map a source into a partial `Finding` deterministically: generic JSON (our published schema, validated directly) or ADO work-item structured fields (repo, file, line, CWE, severity; the field mapping is config) **[D1]** | ADO REST client (read) | `FindingDraft` |
| F0b | `IntakeAgent` | 🤖 | Fill gaps from prose (ADO description, free-text reports): extract the vulnerable location, CWE, attack preconditions, and claimed impact. Each field carries a citation into the source text | Skills: `cwe-*` | `Finding` + per-field confidence |
| F0c | `ResolveLocation` | ⚙️ | Check the extracted file/symbol exists at the revision; fuzzy-match symbol → file:line. If it can't be resolved or confidence is low, the finding goes to `needs_info` instead of a guess | — | `Finding` \| `needs_info` |
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

An agent's configuration is `(model ref, instructions hash, skill set hash, toolset
signature)`. It is recorded on every invocation and can be overridden per run for
experiments. For example: `--override probe_author.model=anthropic:claude-sonnet-5
--override probe_author.skills+=test-junit5-v2`.

### 6.1 Inference backends [D9]

Exactly two backend kinds are supported. A deployment picks one, and any agent can override
it (e.g. for experiments that compare backends):

```yaml
# config/models.yaml  (no secrets in here)
backends:
  bedrock:
    kind: bedrock
    region: us-east-1
    aws_profile: infosec-harness-sso   # an AWS IAM Identity Center (SSO) profile
  gateway:
    kind: openai_compatible
    base_url: https://llm-gateway.internal/v1
    api_key_env: HARNESS_OPENAI_API_KEY   # read from the environment or a secret
    prices: {input_per_mtok: 3.0, output_per_mtok: 15.0}  # used when genai-prices doesn't know the model
default_backend: bedrock
agents:
  probe_author: {backend: bedrock, model: <bedrock-model-id>}
  intake:       {backend: gateway, model: <model-name>}
```

- A small factory turns a `ModelRef(backend, model)` into a pydantic-ai `Model`. No
  wrappers, and no custom client code.
- **Bedrock auth.** Locally, run `aws sso login --profile …` on the host and mount
  `~/.aws` read-only into the `worker` container; botocore refreshes credentials from the
  SSO token cache. In Kubernetes, SSO is not a workload identity, so the same code path
  uses **IRSA / EKS Pod Identity** (the default boto3 credential chain, with the profile
  unset). Credentials never enter agent context or sandboxes.
- **OpenAI-spec auth.** An API key from an env var (compose `.env`) or a k8s Secret. This
  also covers self-hosted servers (vLLM, Ollama) and internal LLM gateways, with no extra
  code.
- Temporal: the model is resolved on the **worker** inside the model activity, so
  credentials are never serialized into workflow history. `TemporalAgent` gets named
  models registered at worker startup.
- Cost: `genai-prices` for known models. Otherwise the backend's configured `prices`
  apply, and costs are recorded as `estimated` when neither is available.

## 7. Sandbox & execution

Probes execute untrusted, LLM-generated code against untrusted repository code, so this
is the main safety boundary.

- **Isolation [D2]: Docker + gVisor (`runsc`).** Every build and probe container runs
  under the gVisor runtime. Locally, `runsc` is registered as a Docker runtime; in k8s it
  is a `RuntimeClass`. One model covers both environments.
- **Local:** one container per prepared image. Network is allowed only during the
  dependency-install build stage, through an egress proxy with an allowlist of package
  registries (see *Package registries* below), and set to `none` at probe time. The container runs as a non-root user,
  with a read-only root filesystem except the probe workdir, cpu/mem/pids limits, and a
  wall-clock timeout.
- **Kubernetes:** each `ExecuteProbe` becomes a short-lived Job/Pod in a dedicated
  namespace with a default-deny NetworkPolicy, `runtimeClassName: gvisor`, and no
  service-account token. Images are built with BuildKit (rootless) in that namespace.
- **Package registries [D14].** Each target repository specifies its own registries in
  its normal config (`settings.xml`/`.mvn`, `gradle.properties`, `pip.conf`/`uv.toml`/
  `pyproject` indexes, `.npmrc`/`.yarnrc.yml`, cpanm `--mirror`). A registry can be public
  or an internal Artifactory. `DetectStack` (deterministic) parses these files into
  `StackFingerprint.registries`, and that list becomes the build-stage egress allowlist.
  Agents cannot add hosts. Artifactory credentials, when needed, are mounted as
  **BuildKit secrets** (`--secret`) for the install step only, so they are never baked
  into image layers or shown to agents. When a repository names no registry, the
  ecosystem's public default is used.
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
  Temporal's history is the source of truth for resumption. **[D3]** The graph can also
  run outside Temporal (plain `Agent`s + `TestModel`) for unit tests and per-agent evals.
- Idempotency: workflow ID = `triage:{finding_fingerprint}:{repo_revision}:{config_hash}`,
  so re-submitting the same finding with the same configuration is de-duplicated.
- **Human-in-the-loop [D8]: asynchronous verdict review.** Runs are fully automated.
  Analysts review, confirm, or override verdicts in the UI/API afterwards. Every override
  is stored with the analyst's reason and **becomes a labelled eval case**: overrides
  feed the "historical triage" corpus (§10.2). There is no blocking approval gate. The
  Temporal update handler (`override_verdict`) is kept, so a gate can be added later.

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
| `artifacts` | Content-addressed blob refs (sha256, size, media type). The bytes live in S3-compatible object storage: MinIO locally, S3 or an equivalent in k8s **[D5]** |
| `verdict_reviews` | Analyst confirm/override, reason, reviewer, timestamp. Exported to eval datasets |
| `ado_sync` | Source work-item ID/rev, write-back status and payload hash (idempotent write-back) |
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
p50/p95 latency/finding.

**Corpus [D7]:**

| Source | Use | Notes |
|---|---|---|
| OWASP Benchmark (Java v1.2, Python) | Large labelled TP/FP set for filtering precision/recall | One app per language, so builds are cheap and cached. Findings are generated from its expected-results CSV in our generic JSON format |
| Real CVE datasets (e.g. Vul4J for Java, BugsInPy/CVEfixes-derived for Python, plus curated JS/Perl CVEs) | Realism: vulnerable commit = exploitable, fixed commit = not exploitable (a paired design) | Slow and brittle builds, so it also serves as the benchmark for **build-agent** success rate |
| Historical internal triage + analyst overrides (D8) | The most representative of production traffic | Needs an export and a labelling pass. It stays private and never goes into the repo; it is loaded from Postgres/MinIO |

Datasets are versioned (`dataset_id@version`) and every experiment records the version.
A small **smoke subset** of each source (~20–50 cases) runs in CI through recorded responses.

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

- **Local:** `docker compose up` starts `postgres`, `temporal` + `temporal-ui`, `worker`,
  `sandbox-worker` (the task queue for build/probe activities), `api` (FastAPI), `web`
  (React UI), `minio`, `otel-collector` + a trace UI **[D4]**, and the build egress proxy
  (§7). Model access goes to Bedrock or the configured OpenAI-spec endpoint **[D9]**; an
  optional `vllm`/`ollama` compose profile serves as a local OpenAI-spec endpoint for
  offline development. The host needs the gVisor `runsc` runtime installed.
- **Kubernetes (later):** Helm chart or Kustomize (the repo already has Kustomize) with
  Temporal via its official Helm chart or Temporal Cloud, managed Postgres, workers as a
  Deployment, and sandbox Jobs in an isolated namespace. KEDA or Temporal worker
  autoscaling is out of scope for v2.0.
- The project uses `uv`, Python 3.12, ruff, and pytest. `just` recipes stay.

### Interfaces [D11]
- **CLI:** `harness submit`, `harness status`, `harness report`, `harness eval run`, and
  `harness eval compare`.
- **REST API (FastAPI):** submit batches (generic JSON / ADO query / free text), fetch
  results, post reviews, and list experiments. The CLI and the UI both use it.
- **Web UI [D12]:** a full React app built with **shadcn/ui**.
  - Stack: Vite + React + TypeScript, shadcn/ui (Radix + Tailwind), TanStack Router,
    TanStack Query, and TanStack Table (via shadcn's data-table). Charts use shadcn charts
    (Recharts). The API client is **generated from FastAPI's OpenAPI schema**
    (`openapi-typescript` + `openapi-fetch`), so front-end types track the Pydantic models.
  - Views:
    - **Triage queue:** a sortable, filterable data table by priority, verdict,
      confidence, CWE, and repo.
    - **Finding detail:** source finding, code context with highlighted lines, probe plan
      and oracle, probe source (diff across repair iterations), execution logs, verdict
      rationale, per-agent cost/latency timeline, and a trace link.
    - **Review:** confirm or override, with a reason.
    - **Batches/runs:** live progress, polled from Temporal via the API.
    - **Experiments:** pick a baseline and a candidate, then compare per-agent and E2E
      accuracy, confusion matrices, $/finding, and p50/p95 latency.
    - **Configuration:** a read-only view of the active agent configs, models, and skill
      versions.
  - Auth: OIDC in front of the API, which is out of scope for phase 1. Locally it is
    single-user.
- **ADO write-back [D13]: comment only.** A Temporal activity at the end of
  `FindingTriageWorkflow` posts **one comment** to the source work item with the verdict,
  priority, confidence, a short evidence summary, and a link to the finding in the UI.
  It never changes state, fields, or tags. Re-runs update the same comment (the comment
  ID is stored in `ado_sync`) instead of posting a new one. It is behind a feature flag
  and uses a PAT scoped to *Work Items (Read & Write)*.

### Proposed repo layout
```
src/infosec_harness/
  domain/           # Pydantic models: Finding, RepoProfile, EnvironmentSpec, ProbePlan, Verdict…
  intake/           # generic JSON schema, ADO adapter, free-text entry
  integrations/ado/ # ADO read + write-back
  agents/<name>/    # agent.py + instructions.md + evals/dataset.yaml
  graph/            # pydantic_graph definitions for prep + triage
  workflows/        # Temporal workflows + activities + worker entrypoint
  sandbox/          # docker / k8s runner behind one interface
  persistence/      # SQLAlchemy models, Alembic migrations, repositories
  evals/            # shared evaluators, experiment runner, compare CLI
  api/ cli/
web/                # UI
skills/             # SKILL.md libraries (lang-*, build-*, test-*, cwe-*)
deploy/compose/  deploy/k8s/
eval-corpus/        # labelled cases (or git submodules / fetch scripts)
```

### Phased delivery (proposal)
1. **Skeleton:** delete v1 code (D10), compose stack, domain models, Postgres schema, a Temporal workflow with
   stub agents (`TestModel`), and a CLI submit/report path.
2. **Python-only vertical slice:** generic JSON + ADO intake, all agents real for pytest
   + 3 CWEs, per-agent eval datasets, the OWASP Benchmark (Python) subset, and a baseline
   experiment.
3. **Evals and experiment comparison tooling:** the compare CLI, recorded-response CI
   evals, and the E2E corpus v1.
4. **Language breadth:** Java (Maven/Gradle + JUnit), JS/React (npm + Jest/RTL), and Perl
   (cpanm + Test::More) as **skills plus eval cases**, with no new agents.
5. **Web UI review queue + ADO write-back**, then **K8s manifests** (gVisor RuntimeClass,
   isolated sandbox namespace).

## 12. Decisions log

| # | Topic | Decision |
|---|---|---|
| D1 | Finding inputs | Generic JSON schema, Azure DevOps work items (structured fields + prose), and free-text reports. **SARIF is not in scope for v2.0.** |
| D2 | Sandbox | Docker + gVisor (`runsc`) locally, and a gVisor RuntimeClass in k8s |
| D3 | Orchestration | The pydantic-graph topology runs inside Temporal workflows. Agents are `TemporalAgent`s |
| D4 | Tracing | Self-hosted OpenTelemetry (collector + trace UI in compose). Nothing leaves the network |
| D5 | Artifacts | S3-compatible (MinIO locally), with refs and hashes in Postgres |
| D6 | Build effort | Aggressive: long repair loops plus partial-build fallback, under hard $ and time caps |
| D7 | Eval corpus | OWASP Benchmark + real CVE datasets + historical internal triage/overrides |
| D8 | Human in the loop | Asynchronous verdict review; overrides become eval cases |
| D9 | Models | Switchable: AWS Bedrock (SSO profile locally, IRSA/Pod Identity in k8s) **or** any OpenAI-spec endpoint with an API key (which also covers self-hosted). Selected per deployment and overridable per agent |
| D10 | v1 code | Delete v1 `src/`, `tests/`, fixtures, and the abox/minikube lab; keep `research/` and design docs as background (done in phase 1) |
| D11 | Interfaces | CLI, REST API, Web UI, and ADO write-back |
| D12 | Web UI | Full React app (Vite + TS) with shadcn/ui, and a client generated from OpenAPI |
| D13 | ADO write-back | One comment per work item, updated in place. No state, field, or tag changes |
| D14 | Package registries | Taken from each repo's own config (public or internal Artifactory); the egress allowlist is derived deterministically; credentials go in as BuildKit secrets |

## 13. Open questions

- **Q15** Default models per agent for the baseline experiment. The proposal: the same
  mid-tier model for every agent as baseline v0, so later experiments change one variable
  at a time. The first planned experiments are a larger model for `ProbeAuthorAgent` and
  `VerdictAgent`, and a smaller model for `IntakeAgent` and `ProbeDiagnosisAgent`.
- **Q17** Which Bedrock model IDs and regions (or cross-region inference profiles) your
  AWS account has enabled, and the OpenAI-spec endpoint(s) you plan to use.
