# Ground-truth eval corpus (seeded starter set)

Small, self-contained apps with a **paired** design: for each CWE, a `vulnerable` and a
`fixed` variant of the same tiny app. The finding submitted for both variants is nearly
identical; only the code differs, so the expected verdicts differ for the right reason.
This is the cleanest ground-truth signal for the whole pipeline and for per-agent evals.

`manifest.json` lists each case with the submitted `finding` and the `truth` used for
scoring (expected verdict, reachability, sink file/line, target callable). Truth is never
shown to the agents.

## Cases (python/)

| Case | CWE | Expected verdict | Exercises |
|---|---|---|---|
| sqli-vulnerable / sqli-fixed | CWE-89 | exploitable / not | SQL injection; structure oracle |
| cmdi-vulnerable / cmdi-fixed | CWE-78 | exploitable / not | command injection; canary-file oracle |
| pathtraversal-vulnerable / -fixed | CWE-22 | exploitable / not | path traversal; sandbox-file oracle |
| xss-vulnerable / xss-fixed | CWE-79 | exploitable / not | output-encoding oracle |
| unreachable | CWE-89 | not exploitable | context marks the sink unreachable (constant query) |
| testonly | CWE-89 | not exploitable | pre-filter early exit (finding is in tests/) |

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
