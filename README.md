# InfoSec Harness

A durable graph of [PydanticAI](https://pydantic.dev/docs/ai/) agents that **filters,
prioritizes, and triages pre-identified vulnerability findings** for exploitability. For
each finding it profiles the target repository, works out how to build and test it, drafts
a targeted unit-test probe, runs the probe in an isolated sandbox, and returns one of
`potentially_exploitable` / `likely_not_exploitable` / `inconclusive` with evidence and a
priority.

It does not scan for new vulnerabilities, write fixes, or touch production. Probes run only
against code in a sandbox. See [`docs/redesign/SPEC.md`](docs/redesign/SPEC.md) for the full
design and decision log.

## How it works

- **Agents are data.** Each of the 11 agents is one pydantic-ai Agent Spec
  (`agents/<name>/agent.yaml`): a prompt, a model tier, cache settings, and a skills list.
  Typed I/O, the capability allowlist, and the verdict contract stay in code. Skills
  (`skills/*/SKILL.md`) give per-CWE, per-language, per-framework guidance on demand.
- **Two Temporal workflows.** `RepoPreparationWorkflow` runs once per repo@revision
  (recon → environment plan → build with an aggressive repair loop and a partial-build
  fallback → smoke test) and is cached. `FindingTriageWorkflow` runs the per-finding graph
  (context → probe plan → author → execute → diagnose → repair loop → verdict). The
  pydantic-graph topology runs *inside* the workflow; agents are `TemporalDurability` agents
  whose model and tool calls become activities.
- **Deterministic where it counts.** Stack detection, building, probe execution, the
  three-way verdict contract, prioritization, and cost accounting are plain code. Probes
  decide exploitability from an explicit oracle signal, never from a passing test.
- **Sandbox.** Build and probe containers run under gVisor (`runsc`), non-root,
  read-only-root, resource-capped, and with **no network at probe time**.
- **Models.** Switchable per deployment and per agent: AWS Bedrock (SSO profile locally,
  IRSA in k8s) or any OpenAI-spec endpoint with an API key. A `stub` mode runs the whole
  pipeline deterministically with no credentials.
- **Prompt caching.** A stable→volatile prompt layout, pinned model/thinking per agent, and
  repo-grouped warm-then-fan-out scheduling keep the shared prefix served from cache; cache
  tokens are recorded per call.
- **Evidence-based tuning.** Every agent has an eval dataset; `harness eval run` /
  `eval compare` measure the accuracy, cost, and latency impact of any model/prompt/skill
  change, one variable at a time.

## Quick start (offline, no credentials)

```bash
just bootstrap          # uv sync
just check              # ruff + compile + validate all agent specs
just test               # full suite, stub models, SQLite (Temporal test needs the `temporal` CLI)
just demo               # run the full pipeline in-process on examples/findings.sample.json
```

`just demo` prints a verdict and priority per finding. In `stub` mode verdicts are
deliberately `inconclusive` (the stub is not a real judge) — it exercises the plumbing, not
accuracy. What a *live* model does — per-class accuracy, tool/skill evocation, and the
endpoint-compatibility problems stubs cannot show — is in
[`docs/LIVE_VALIDATION.md`](docs/LIVE_VALIDATION.md).

## Full stack

```bash
docker compose up --build
```

Starts Postgres, Temporal (+ UI at :8233), MinIO (:9001), an OpenTelemetry collector with
Jaeger (:16686), the worker, the API (:8000, docs at `/docs`), and the web app (:8080).

- **Stub models** are the default, so the stack runs with no credentials.
- **Bedrock:** `aws sso login --profile infosec-harness-sso` on the host, then
  `HARNESS_MODEL_MODE=live docker compose up` (mounts `~/.aws`).
- **OpenAI-spec:** `HARNESS_MODEL_MODE=live HARNESS_MODEL_BACKEND=gateway
  HARNESS_OPENAI_API_KEY=sk-… docker compose up` (edit the endpoint in `config/models.yaml`).
- **No gVisor on the host:** `HARNESS_SANDBOX_RUNTIME=runc docker compose up` (weaker
  isolation; for local development only).

> Building the images requires normal registry/PyPI access. Behind a TLS-inspecting proxy,
> drop the proxy CA at `deploy/extra-ca.crt` (gitignored) and it is trusted in the build.

## CLI

```bash
harness submit findings.json [--local]   # triage a batch (JSON: one finding, a list, or {findings:[...]})
harness runs [--verdict … --batch-id …]  # list runs, highest priority first
harness report <run-id>                  # full triage report as JSON
harness eval run <agent> [--overlay … --repeat N]   # run an agent's eval dataset
harness eval corpus [--language all --repeat N --no-sandbox]  # score the ground-truth corpus
harness eval compare <exp-a> <exp-b>     # accuracy / cost / latency deltas
harness worker | harness api | harness init-db
harness agents validate | agents schema
```

## Layout

```
agents/<name>/agent.yaml   # the 11 agent specs (+ evals/dataset.yaml)
skills/                    # SKILL.md libraries: probe-oracle-protocol, cwe-*, lang-*, build-*, test-*
src/infosec_harness/
  domain/         # typed contracts (Finding, EnvironmentSpec, ProbePlan, Verdict, …)
  agents/         # loader, model factory, custom capabilities, stubs, validators
  graph/          # pydantic-graph triage flow, prepare orchestrator, Ops interface, scoring
  workflows/      # Temporal workflows, activities, TemporalOps, worker, runner
  sandbox/        # gVisor-capable Docker runner
  persistence/    # SQLAlchemy models, store, artifact store (MinIO/filesystem)
  intake/ integrations/ado  # generic JSON + Azure DevOps intake and comment-only write-back
  evals/          # per-agent eval runner and compare
  api/ cli.py     # FastAPI service and Typer CLI
web/              # React + shadcn triage UI (client generated from the API's OpenAPI)
deploy/           # compose support (postgres init, otel collector)
```
