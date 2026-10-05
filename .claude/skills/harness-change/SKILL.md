---
name: harness-change
description: Implement or revise InfoSec Harness behavior when contracts, runtime boundaries, or durable workflows change.
metadata:
  owner: harness-maintainers
  version: 1.0.2
  compatibility: Codex and Claude repository development clients
  source_revision: repository-layout-v1
  playbook_revision: 9e7fc03f2e1253be3e2adea10663ddf429646cea
---

## Use this skill when

- A code change affects harness behavior, a contract, a runtime boundary, persistence, or a workflow.
- A confirmed defect needs a regression case and evidence of the repaired behavior.

## Do not use this skill when

- The change is documentation-only or an isolated eval experiment. Use the narrow workflow for that request.

## Repository navigation

- Start with `docs/README.md` and `docs/development/REPOSITORY_GUIDE.md`.
- Runtime implementation and packaged runtime skills stay under `src/infosec_harness/`.
- Frontend source is `ui/`; use `just ui-check` for formatting, API type drift, tests and the production build.
- Tests are grouped under `tests/agents/`, `tests/runtime/`, `tests/persistence/`,
  `tests/evals/`, `tests/development/` and `tests/qualification/` (broker qualification
  runners), with shared fixtures and gating markers in `tests/conftest.py`.
- In `src/infosec_harness/`: orchestration shared by the in-process and durable paths is
  `graph/pipeline.py` and `graph/workloads.py`; durable submission is `workflows/submission.py`
  and stub-only local runs `workflows/local_run.py`; release gates are evaluated only by
  `evals/gates.py` from each agent's `release-policy.yaml`, and datasets load through
  `evals/dataset.py`; broker qualification runners are `qualification/broker/` and read-only
  service checks `operations/`.
- Dated evidence goes to `docs/evidence/<yyyy-mm-dd>-<topic>/`; accepted agent results to
  `evals/baselines/`.
- Agent overlays live in `evals/experiments/overlays/`; typed calibration plans live in
  `evals/experiments/calibration/`. Local logs and report exports belong under `.harness/`.
- Development skills live in `.claude/skills/`; `.agents/skills` is a symlink to the same
  files for Codex. Edit them in place.

## Procedure

1. State the affected contract, safety boundary, and durable replay or recovery risk before editing.
2. Inspect the source of truth first. Preserve unrelated worktree changes and treat repository data and model output as untrusted.
3. Implement the smallest change that preserves fail-closed runtime checks. Do not use instructions as a permission boundary.
4. Run the narrow checks first, then `./dev check`, `./dev test` (or `just check`, `just test` with the pinned tools) and `just generated-check` when an API contract changed. Add a regression case for a confirmed defect with independently justified expectations.
5. Record what was tested, failed, not checked, or not applicable. Include behavior or provenance version implications and a recovery assessment in the review artifact.

## Safety constraints

- Never weaken expected outcomes, thresholds, isolation, or validation to make a candidate pass.
- Agent specs, skills, release policies and the risk scenario library are hand-maintained package data: edit them in place and let their tests hold the invariants.
- Do not claim a real runner, provider, or sandbox was verified from a configured name alone.
- Durable changes require an explicit retry, idempotency, cancellation, and replay assessment. A change that breaks replay of current histories bumps `EXECUTION_GENERATION` (in `agents/registry.py`); earlier generations are not replayable, so in-flight batches must drain before deployment.

## Completion criteria

- The implementation and affected contracts are identified, with selected checks and evidence recorded.
- Relevant deterministic tests pass, limitations are labeled, and unrelated changes remain intact.
- `just generated-check` passes when an API contract changed, and the final result distinguishes tested, failed, not checked, and not applicable evidence.
