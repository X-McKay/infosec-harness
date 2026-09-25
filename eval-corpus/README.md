# Ground-truth eval corpus (seeded starter set)

Small, self-contained apps with a **paired** design, across **Python, Java, JavaScript, and
Perl**: for each (language, CWE), a `vulnerable` and a `fixed` variant of the same tiny app. The finding submitted for both variants is nearly
identical; only the code differs, so the expected verdicts differ for the right reason.
This is the cleanest ground-truth signal for the whole pipeline and for per-agent evals.

`manifest.json` lists each case with the submitted `finding` and the `truth` used for
scoring (expected verdict, reachability, sink file/line, target callable). Truth is never
shown to the agents.

## Cases (22 total)

Each case name is `[<lang>-]<cwe>-<variant>` (Python cases are unprefixed).

| Language (toolchain) | CWEs (paired vulnerable/fixed) |
|---|---|
| python (pip / pytest) | CWE-89 SQLi, CWE-78 cmdi, CWE-22 path traversal, CWE-79 XSS |
| java (maven / junit5) | CWE-89 SQLi, CWE-78 cmdi |
| javascript (npm / jest) | CWE-78 cmdi, CWE-79 XSS |
| perl (cpanm / Test::More) | CWE-89 SQLi, CWE-78 cmdi |

Plus two Python edge cases: `unreachable` (sink present but only ever called with a constant
query — context should mark it unreachable) and `testonly` (the flagged pattern is under
`tests/` — the pre-filter should early-exit).

Every case's ground truth includes the exact sink file/line and target callable, and
`test_corpus.py` asserts `detect_stack` identifies the right language, build system, and test
framework for each.

## How it's used

- `infosec_harness.evals.corpus.load_corpus()` yields typed `CorpusCase`s (findings +
  ground truth), with `repo_url` resolved to an absolute path.
- End-to-end: run each `finding` through the pipeline and compare the verdict to
  `expected_verdict` (per-class precision/recall; the false-negative rate on vulnerable
  cases is the headline metric).
- Per-agent: `context` recall is scored against `sink_file`/`sink_line`; `probe_author`
  and `env_planner` are scored by execution (does it build, does the oracle fire on the
  vulnerable variant and not the fixed one).

Adding a case: create `python/<case>/<variant>/` (app + `requirements.txt` + `tests/`) and
add an entry to `manifest.json`. `tests/test_corpus.py` checks the manifest stays consistent
with the code.
