# Verification

Tests mirror the package layout and cover contracts, source confinement, bounded processes,
agent tools, model serialization, API state projection, evidence gates, native adapter
admission and full-cohort evaluation accounting. Temporal tests start the pinned real local
service to exercise replay, restart, cancellation and unknown execution. Set
`HARNESS_TEST_REQUIRE_TEMPORAL=1` (as `./dev test` does) to make a missing Temporal CLI a
failure rather than a skip.

| Directory | Covers | Tests |
| --- | --- | ---: |
| `agents/` | evidence parsing, model transport, the investigator and the packaged skill catalog (frontmatter, size, catalog budget) | 431 |
| `tools/` | the execute/run_probe wrapper and the confined file tools | 49 |
| `workflows/` | the investigation workflow on a real local Temporal, source snapshots and the worker identity | 64 |
| `sandbox/` | the OpenShell adapter's admission and named boundary checks, the model executor and the owned process runner | 163 |
| `evals/` | cohort evaluation and `--keep-going`/`--parallel` accounting, qualification, and corpus hygiene (no labels in agent inputs) | 144 |
| `development/` | `./dev` (with stub tools), `scripts/dev_setup.py`, the OpenShell artifact and guest helpers | 96 |
| top level | `api.py`, `cli.py`, `config.py`, `contracts.py`, `_io.py` and the installed package | 119 |

That is 1,066 tests, one of them marked `network` (installed-package checks that download
packages; `just test-network`), so `just test` runs 1,065. Counts are as of this file's last
edit; `pytest --collect-only -q -m "not network"` gives the current figure. `conftest.py`
clears every `HARNESS_*` variable except `HARNESS_TEST_*` and resets the bound settings around
each test; `fakes.py` holds the shared fake OpenShell adapter and scripted model-response
helpers, which are never isolation or quality evidence.

Other suites live beside their code: the UI's `node:test` unit tests and Playwright
end-to-end specs (`ui/README.md`), and the corpus fixtures' maintainer tests under
`eval-corpus/verification/`, run by `scripts/corpus_verify.py` and never part of a snapshot.

Ordinary tests block ambient model requests. `harness qualify` supplies separate native
OpenShell evidence; `harness eval --allow-inference` supplies separately authorized live
model evidence. Mocked tests never stand in for either gate.
