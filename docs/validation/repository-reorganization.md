# Repository reorganization — 2026-10-01

## Delivered layout

- Frontend source is now `ui/` (lowercase), including its ignored local dependencies and build
  output. `just ui-build` and `just ui-check` are canonical; old `web-build` and `web-check`
  recipes remain aliases. Launcher dependency installation, Compose build/mount paths, CI,
  OpenAPI tooling, Ruff exclusions, Git ignores and Docker build exclusions use `ui/`.
- Historical agent overlays are under `evals/experiments/overlays/`, with their README and
  negative-result annotations preserved. Typed calibration inputs are under
  `evals/experiments/calibration/`. The root `experiments/` directory is removed.
- Documents are grouped under `docs/development/`, `docs/architecture/`, `docs/evaluation/`
  and `docs/validation/`. `docs/README.md` remains the navigation entry point. Generated risk
  assessments and threat models stay at their contracted paths.
- Tests are grouped under `tests/agents/`, `tests/runtime/`, `tests/persistence/`, `tests/evals/`
  and `tests/development/`. Shared fixtures remain at `tests/conftest.py`. The test README
  describes focused commands and distinguishes synthetic target paths from repository paths.

All 106 files in the move inventory were verified present at their new locations. Repository
references, Markdown links and test root calculations were updated. Runtime/governance evidence
paths were updated in their source libraries and regenerated with `just governance`.
`CLAUDE.md` was regenerated from the canonical `AGENTS.md`; development skill content remains
unchanged and both generated client copies pass drift checks. The separately authored untracked
`docs/CREDENTIAL_BROKER_SPEC.md` draft was preserved at its original path.

New layout checks verify that the base Compose build context and editable development mount
resolve to the same existing frontend tree, and that report/log/build/cache outputs stay ignored
by Git. These checks run with the deterministic test suite, without Docker. The full suite
caught accidental changes to two synthetic fixture paths during migration; those fixtures were
restored rather than adapting expected results to the directory move.

## Contracts, provenance and recovery

This changes repository paths and developer entry points, not workflow topology, activity
identities, verdict logic, isolation controls, retry/cancellation policies or database schemas.
No state migration or Temporal replay patch is needed. Packaged agents, skills, tools and
migrations retain their resource locations. Evidence-reference comments and generated skill text
now point at the moved docs/tests; source and configuration digests naturally reflect those
content changes. No behavioral contract, evaluator or provenance schema version bump is required.

The Compose service remains `web`; its port settings, project identity and named volumes remain
stable. Existing workspace, database, artifacts, reports, logs and VM state are preserved.
Recreate the managed stack with `./dev` to apply the new source mount; a restart alone does not
change a container's existing mount. `./dev stop` preserves data. No running stack was stopped,
recreated or reset during this review.

External scripts using old repository paths must update to the new locations. Compatibility
aliases cover existing `just web-build`/`web-check` calls. Existing persisted experiment labels
may refer to historical overlay paths; their recorded effective configuration and results are
not rewritten. New runs use the relocated input paths. Temporary export idempotency, atomic
publication, interrupted-run persistence and retention behavior from the cleanup are unchanged.

## Validation

| Gate | Status | Evidence |
| --- | --- | --- |
| `just check` | passed | Ruff, compilation and agent validation after the lowercase rename |
| `just generated-check` | passed | OpenAPI, shared instructions and development skill copies |
| `just dev-skills-check` | passed | Canonical development skills and client copies match |
| Focused moved/layout tests | passed | 45 tests: Compose paths, ignored outputs, component detection, developer tooling, ecosystem evidence and calibration |
| Frontend checks | passed | Formatting, two search tests, TypeScript and Vite build from `ui/`; client regeneration is byte-identical to the committed generated types |
| Move inventory / local Markdown links | passed | All 106 destinations exist; maintained documentation has no missing relative file targets |
| Shell syntax / whitespace | passed | `bash -n dev`; `git diff --check` |
| Full suite | failed | 1,512 passed, 11 skipped, two previously reproduced installed-wheel dependency failures; `.harness/reorganization-test-final.log` |
| Managed runtime / Compose deployment | not_checked | Static Compose paths tested; Docker/VM not started and actual isolation/log-driver checks not rerun |
| Temporal integration | not_checked | 11 optional real-service integration tests skipped |
| Live models / clean-host acceptance / external conformance | not_checked | No provider calls, fresh-host setup or agentctl execution |
| State/database migration | not_applicable | Durable state paths and schema are unchanged |

The known wheel failures come from unconstrained installation resolving newer PydanticAI/Temporal
versions than `uv.lock`, producing a Pydantic schema-generation error for Temporal `EventGroup`.
The prior cleanup reproduced this on unmodified HEAD. Dependency ranges and test expectations
are unchanged; see [repository-cleanup.md](repository-cleanup.md).
