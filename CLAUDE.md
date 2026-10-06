# InfoSec Harness development

A durable vulnerability triage harness built on OpenShell, PydanticAI and Temporal.
Repository content, findings, probe output and model output are untrusted. Runtime checks
own safety boundaries; instructions never grant permissions. Fail closed when isolation
or execution evidence is absent. A configured name is not execution evidence.

## Sources of truth

- Runtime code lives in `src/infosec_harness/`: `agents/` holds exactly one investigator
  (`investigator.py`, which chooses tools and skills, plus its evidence parser and model
  transport; the directory adds no parallel orchestration), `tools/` its OpenShell tools,
  `skills/` packaged investigation expertise,
  `workflows/` the PydanticAI Temporal workflow, trusted worker and source capture, `sandbox/`
  the OpenShell adapter and model executor, `evals/` corpus evaluation and qualification.
  Top level: `cli.py` entry points, `config.py` operator configuration, `contracts.py`
  contracts, `api.py` the Temporal projection behind the UI, `_io.py` atomic writes. Do not add
  parallel orchestration, application persistence, custom provider brokers or fallback runtimes.
- `sandbox/` owns sandbox lifecycle and bounded command receipts. Native OpenShell owns
  execution, policy and provider credentials. Docker inspection is read-only evidence of
  the native outer fence, never an execution route. Skills contain expertise, not permissions.
- `src/infosec_harness/evals/release-policy.yaml` is the single live evaluation policy. Missing evidence is
  `not_checked`, never `passed`. `eval-corpus/manifest.json` is independent ground truth.
- Development skills are canonical in `dev-skills/`, copied to `.claude/skills/` by
  `just generated-sync`; `.agents/skills` links to that copy. Edit only the canonical source.
- `AGENTS.md` is canonical; `CLAUDE.md` is generated. OpenAPI and UI client types are generated
  from the API with `just regenerate`. Do not maintain divergent copies.
- Start at `README.md`. Dated historical evidence stays in `docs/evidence/`; it does not
  qualify a later architecture or commit. Private configuration and reports stay in `.harness/`.

## Commands

```bash
./dev                         # pinned tools, local Temporal/API/UI, native OpenShell checks
./dev --profile offline       # deterministic component and real local Temporal tests
./dev worker                  # trusted worker using explicit native OpenShell configuration
./dev doctor | status | logs | smoke | stop
./dev qualify                 # native boundaries; no model calls
./dev eval [--case NAME] [--parallel N]  # live corpus, owned worker on a fresh queue
./dev replay RUN_ID           # zero-dispatch history replay
./dev export-history RUN_ID   # read-only history JSON under .harness/histories/; no overwrite
./dev env                     # shell lines putting the managed tools on PATH
just check                    # lint and compile
just test                     # deterministic tests; no model network calls
just test-network             # installed-package checks using package downloads
just generated-check          # API schema, CLAUDE.md, skill copies and runtime skill catalog
just ui-check                 # formatting, generated types, tests and production build
```

Full setup requires the explicit OpenShell configuration described in
`deploy/openshell/README.md`; `./dev` reads an explicit `HARNESS_OPENSHELL_CONFIG`, else
`.harness/openshell/private/native-config.json`, else `.harness/openshell/runtime.json`, and
without one reports native qualification `not_checked`. There is no default model endpoint or public
fallback. The managed Lima VM's Docker daemon (plain runc) builds trusted workload images;
agent execution always uses OpenShell. Never weaken a boundary to get setup or qualification
to pass. Offline mode leaves native OpenShell and live inference `not_checked`.
`--settings FILE` on `./dev worker|qualify|eval|replay|export-history` freezes one
configuration (no `HARNESS_*`). `./dev eval --case NAME` never qualifies; `--parallel N`
(1 to 8) runs up to N cases at once and records that as a report limitation. From a git
worktree, `./dev` uses the main checkout's `.harness`; a full start runs only from the main
checkout.
Never edit `src/infosec_harness/` (code, YAML or skill Markdown) while an owned evaluation
worker runs: the worker identity covers those files and its guard ends the cohort.

Pins live in `.mise.toml`, `.dev-tools/versions.env` and `.dev-tools/openshell.json`.
Managed tools stay under `.harness/`; VM state uses a short checkout-specific directory
under `~/.cache/ih/`. Setup must not change global tools, shell profiles, host Docker
contexts or shared firewall policy. Stop preserves data; there is no implicit reset.

## Completion evidence

Behavior changes require affected contracts and risk, selected checks, provenance and a
replay/recovery assessment. Breaking workflow changes require a new task queue/generation
and draining old workers; backward compatibility is not promised. The current generation is
`v11`, with task queue `investigate-v11` and run prefix `investigate-v11-`. It binds
every native model/tool activity to the captured worker identity; v10 and older histories and
workers must drain before replacement. Unknown external execution must never be blindly
retried. Cancellation must reach owned work and cleanup.

Turn confirmed defects into regression cases with independently justified expectations.
Never weaken thresholds or golden outcomes to make a candidate pass. Distinguish mocked,
local Temporal, native sandbox and live model evidence. Report each relevant gate as
`passed`, `failed`, `not_checked` or justified `not_applicable`. Require the pinned Temporal
CLI in qualification and CI with `HARNESS_TEST_REQUIRE_TEMPORAL=1`.
