# Evaluation evidence

The active end-to-end evaluator is `src/infosec_harness/evals/cohort.py`; its policy is the
packaged `release-policy.yaml` and its unchanged paired inputs live in `eval-corpus/`.
Run it with `./dev eval` against a clean commit (see
[qualification and evaluation](../deploy/openshell/README.md#qualification-and-evaluation)).

`heldout/` retains sealed stage-specific fixtures from the former architecture; they are not
runnable through the new investigator and do not establish held-out coverage. They need
independently reviewed conversion before a new held-out claim. Do not delete or rewrite their
golden labels to make a candidate pass. New deterministic safety regressions live under `tests/`.

Private run output goes under `.harness/`; dated reviewed evidence goes under `docs/evidence/`.
No run automatically promotes a model or baseline.
