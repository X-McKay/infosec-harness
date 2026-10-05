# InfoSec Harness

A durable graph of [PydanticAI](https://pydantic.dev/docs/ai/) agents that **filters,
prioritizes, and triages pre-identified vulnerability findings** for exploitability. For each
finding it profiles the target repository, works out how to build and test it, drafts a targeted
unit-test probe, runs the probe in an isolated sandbox, and returns one of
`potentially_exploitable` / `likely_not_exploitable` / `inconclusive` with evidence and a
priority.

It does not scan for new vulnerabilities, write fixes, or touch production. Probes run only
against code in a sandbox.

## Quickstart

On Apple Silicon macOS or Debian/Ubuntu x86-64 Linux, clone the repository and run:

```bash
./dev
```

The launcher installs pinned tools and locked dependencies, provisions a checkout-owned Lima VM
with Docker and gVisor (`runsc`) without changing host Docker configuration, verifies the
sandbox and build-egress fixtures, starts the stack, and runs a stub assessment through the API
and the Temporal worker. It prints the web, API, Temporal UI and log locations when ready.
Inference is stubbed by default, so no provider is contacted. Run `./dev reload` after backend
edits; web edits reload through Vite. `./dev stop` stops this checkout's stack and preserves its
VM, volumes and findings; `./dev reset` is the only command that deletes them.

On a host without hardware virtualization, `./dev --profile offline` runs the locked lint,
agent validation and deterministic test suite with stub models. It reports the API, Temporal,
web, persistence and real sandbox gates as `not_checked`; it is not a full-stack result.

[Local setup](docs/development/LOCAL_SETUP.md) covers host requirements, every `./dev` command,
live models, migrations and troubleshooting.

## Find your way around

- [Documentation index](docs/README.md): setup, architecture, safety, evaluation and evidence.
- [Repository guide](docs/development/REPOSITORY_GUIDE.md): module map, output locations and
  directory conventions.
- [Developer scripts](scripts/README.md), [UI](ui/README.md), [deployment](deploy/README.md),
  [eval inputs](evals/README.md) and [fixture corpus](eval-corpus/README.md).

## How it works

- **Agents are data.** Each of the 11 agents is one PydanticAI Agent Spec
  (`src/infosec_harness/agents/<name>/agent.yaml`): a prompt, a model tier, cache settings and a
  skills list. Typed I/O, the capability allowlist and the verdict contract stay in code. Skills
  (`src/infosec_harness/skills/<name>/SKILL.md`) give per-CWE, per-language and per-toolchain
  guidance on demand.
- **Durable orchestration.** `TriageBatch` groups findings by repository, prepares each
  compatible component once (`ComponentPreparation`: recon, environment plan, build with a
  bounded repair loop and a partial-build fallback, smoke test), then fans the findings out
  (`FindingTriage`: context, probe plan, author, execute, diagnose, repair, verdict). The same
  pipeline code runs in-process for stub demos and tests. See
  [the triage system](docs/architecture/TRIAGE_SYSTEM.md).
- **Deterministic where it counts.** Stack detection, building, probe execution, the three-way
  verdict contract, prioritization and cost accounting are plain code. Exploitability is decided
  from an explicit oracle signal, never from a passing test.
- **Sandbox.** Build and probe containers run under gVisor, non-root, read-only root,
  resource-capped, and with no network at probe time. Any runtime other than `runsc` is refused
  unless `HARNESS_ALLOW_INSECURE_RUNTIME=true` is set for local development.
- **Models.** AWS Bedrock or an operator-configured OpenAI-compatible endpoint; one backend,
  selected per deployment, serves every agent. `stub` mode runs the whole pipeline
  deterministically with no credentials.
- **Prompt caching.** A stable-to-volatile prompt layout, pinned model settings per agent and
  repository-grouped warm-then-fan-out scheduling keep the shared prefix cached;
  `tests/agents/test_cache_prefix.py` and `tests/agents/test_exploration_cost.py` check both.
- **Evidence-based tuning.** Every agent has an eval dataset and a release policy.
  `harness eval run <agent> -m sonnet -m opus` runs one dataset against each model in turn, and
  accepted results are committed under [`evals/baselines/`](evals/baselines/README.md).
- **Governed.** Each agent declares an owner, execution class, governance tier, data
  classification, model policy and an enforced per-run budget; its tier must match the risk
  scenarios it carries. See [playbook conformance](docs/architecture/PLAYBOOK_CONFORMANCE.md)
  and the [threat model](docs/threat-models/triage-system.md).

## CLI

```bash
harness submit findings.json [--local]   # triage a batch; --local is an in-process stub demo
harness runs [--verdict ... --batch-id ...]  # list runs, highest priority first
harness report <run-id>                  # full triage report as JSON
harness migrate                          # upgrade HARNESS_DATABASE_URL to the migration head
harness init-db                          # create an empty database at head (tests, demos)
harness readiness | model-connectivity --model  # read-only service checks
harness worker | harness api
harness agents validate | agents schema
harness eval run <agent> [-m sonnet -m opus] [--repeat N] [--dataset PATH] [--report-dir DIR]
harness eval corpus [--language all] [--manifest PATH] [--limit N] [--no-sandbox]
harness eval results | compare | calibrate
harness eval baseline save <experiment-id> | baseline list
```

`-m`/`--model` names a model-catalogue tier (`opus`, `sonnet`, `haiku`), never a raw model id.

`just demo` runs the pipeline in-process on `examples/findings.sample.json` with stub models;
its verdicts are deliberately `inconclusive` because the stub is not a judge.

## Layout

Anything an agent needs in order to run is package data and ships in the wheel; anything
reviewers and CI read about the system stays at the repository root.

```
src/infosec_harness/
  agents/<name>/        # the 11 agent specs, eval datasets and release policies
  agents/risk-scenarios.yaml  # scored harm scenarios, their controls, and which agents carry each
  agents/*.py           # loader, registry, model factory, capabilities, renderer, validators
  skills/               # runtime SKILL.md files: probe-oracle-protocol, cwe-*, lang-*, build-*, test-*
  config/               # model catalogue and the disabled reference broker catalog
  tools/                # per-toolset policy (effect, retry safety, timeout, output bound)
  domain/               # typed contracts (Finding, EnvironmentSpec, ProbePlan, Verdict, ...)
  graph/                # triage graph, preparation, shared pipeline and workloads, scoring
  workflows/            # Temporal workflows, activities, submission, local runs, worker
  sandbox/              # gVisor Docker runner, isolation policy, bounded subprocesses
  repo/                 # hardened checkout, access checks, component and stack detection
  persistence/          # run store, artifacts, accounting, recipe cache, alembic migrations
  inference/            # opt-in credential broker: wire, catalog, worker, controller, executor, native
  evals/                # datasets, adapters, gates, reports, baselines, corpus and calibration
  operations/           # read-only readiness and model-connectivity checks
  qualification/broker/ # operator broker qualification runners (not imported by serving code)
  api/ cli.py           # FastAPI service and Typer CLI
  intake/ integrations/ # JSON intake and Azure DevOps comment-only write-back
docs/                   # documentation index, living docs, and dated evidence under evidence/
eval-corpus/            # paired vulnerable/fixed fixture repositories and ground truth
evals/                  # committed baselines, held-out sets, calibration plans and overlays
examples/               # sample findings for the demo
scripts/                # setup, validation, broker qualification and measurement tools
tests/                  # agents, runtime, persistence, evals, development and qualification
ui/                     # React triage UI (API types generated from the OpenAPI document)
deploy/                 # compose support, egress proxy, dev VM, Kubernetes and OpenShell
.claude/skills/         # development skills (.agents/skills is a symlink for Codex)
.harness/               # ignored local state: tools, workspace, reports and log snapshots
```

Specs address their resources by path inside the distribution, and `infosec_harness.resources`
resolves them through `importlib.resources`, never relative to the working directory.
`tests/development/test_packaging.py` builds and installs the real wheel and constructs all 11
agents from an unrelated directory.
