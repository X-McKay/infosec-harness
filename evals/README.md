# Evaluation evidence

The active end-to-end evaluator is `src/infosec_harness/evals/cohort.py`; its policy is the
packaged `src/infosec_harness/evals/release-policy.yaml` (at least 75% correct verdicts, zero
unsafe negatives, the complete corpus) and its unchanged paired inputs are the 82 de-labelled
cases in [`eval-corpus/`](../eval-corpus/README.md). Run it with `./dev eval` against a clean
commit (see
[qualification and evaluation](../deploy/openshell/README.md#qualification-and-evaluation)).

`eval-corpus/README.md` contains the maintainers' answer key, and `eval-corpus/manifest.json`
and `eval-corpus/verification/` hold the same truth. Never copy any of it, or any mapping
from a fixture directory to a verdict, into a finding, prompt, skill, fixture or anything else
an agent reads.

`heldout/` retains sealed stage-specific fixtures from the former architecture; they are not
runnable through the new investigator and do not establish held-out coverage. They need
independently reviewed conversion before a new held-out claim. Do not delete or rewrite their
golden labels to make a candidate pass. New deterministic safety regressions live under `tests/`.

Private run output goes under `.harness/`; dated reviewed evidence goes under `docs/evidence/`.
No run automatically promotes a model or baseline.
