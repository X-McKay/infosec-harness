---
name: harness-eval-experiment
description: Run a controlled InfoSec Harness experiment on prompts, models, tools, skills or orchestration.
---

Use this skill for measured behavior changes. Read `AGENTS.md`, `evaluation.py`, the
packaged `release-policy.yaml` and the corpus manifest before running a comparison.

1. Record the hypothesis, frozen source identity, dataset, model, native runtime
   configuration, limits and authorized inference scope.
2. Run deterministic checks first. Mocked model tests never count as quality evidence.
3. Run `./dev qualify`, then the complete agreed cohort once with `./dev eval [--settings FILE]
   [--keep-going]`: an owned worker on a fresh task queue, through the ordinary Temporal
   investigation path, writing a new timestamped report under `.harness/reports/`. Put the
   frozen settings file beside the private cohort evidence. `./dev eval --case NAME` is a
   diagnostic and never qualifies; `./dev replay RUN_ID` replays a history with zero dispatch.
   Never edit `src/infosec_harness/` while an owned worker runs: the identity guard ends the
   cohort. Preserve failed and unstarted cases, unknown execution/cost and the original
   report. Never blindly retry a model dispatch.
4. Compare the same cases, limits and scoring rules. Inspect per-language and safety
   regressions; distinguish inconclusive results from correct negative verdicts.
5. Record provenance, budget usage, failures, limitations and a promotion recommendation.
   No automatic promotion or claim of improvement without a comparable baseline.

Experiments do not authorize additional paid providers, expanded network access or modified
ground truth. Keep golden labels out of agent inputs. Required gates are `passed`, `failed`,
`not_checked` or justified `not_applicable`. Real sandbox, Temporal and provider evidence
must be reported separately. Dated evidence belongs under `docs/evidence/`; private reports
and configuration belong under `.harness/`.
