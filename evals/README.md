# Evaluation evidence

The active end-to-end evaluator is `src/infosec_harness/evaluation.py`; its policy is the
packaged `release-policy.yaml` and its unchanged paired inputs live in `eval-corpus/`.
Run it with `harness eval --allow-inference --output <new-file>` against a clean commit.

`baselines/` retains explicitly accepted historical results. `heldout/` retains sealed
stage-specific fixtures from the former architecture; they are not runnable through the
new investigator and do not establish held-out coverage. They need independently reviewed
conversion before a new held-out claim. Do not delete or rewrite their golden labels to
make a candidate pass. New deterministic safety regressions live under `tests/`.

Private run output goes under `.harness/`; dated reviewed evidence goes under `docs/evidence/`.
No run automatically promotes a model or baseline.
