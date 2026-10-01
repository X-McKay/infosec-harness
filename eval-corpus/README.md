# Ground-truth eval corpus (seeded starter set)

Small, self-contained apps with a **paired** design, across **Python, Java, JavaScript, and
Perl**: for each (language, CWE), a `vulnerable` and a `fixed` variant of the same tiny app. The finding submitted for both variants is nearly
identical; only the code differs, so the expected verdicts differ for the right reason.
This is the cleanest ground-truth signal for the whole pipeline and for per-agent evals.

`manifest.json` lists each case with the submitted `finding` and the `truth` used for
scoring (expected verdict, reachability, sink file/line, target callable). Truth is never
shown to the agents.

## Cases (32 total)

Each case name is `[<lang>-]<cwe>-<variant>` (Python cases are unprefixed).

| Language (toolchain) | CWEs (paired vulnerable/fixed) |
|---|---|
| python (pip / pytest) | CWE-89 SQLi, CWE-78 cmdi, CWE-22 path traversal, CWE-79 XSS, CWE-94 code injection, CWE-502 deserialization, CWE-611 XXE, CWE-918 SSRF |
| java (maven / junit5, release 17) | CWE-89 SQLi, CWE-78 cmdi |
| java (maven / **junit4**, source 1.7) | CWE-611 XXE |
| javascript (npm / jest) | CWE-78 cmdi, CWE-79 XSS |
| perl (cpanm / Test::More) | CWE-89 SQLi, CWE-78 cmdi |

Plus two Python edge cases: `unreachable` (sink present but only ever called with a constant
query — context should mark it unreachable) and `testonly` (the flagged pattern is under
`tests/` — the pre-filter should early-exit).

The two JVM rows are the point of the `java-xxe` pair. The seeded Java cases were all JUnit 5
on `maven.compiler.release` 17, and of the 51 Maven entries harvested from Vul4J into
`external/vul4j.json`, 50 are JUnit 4 and 14 declare Java 7 — so every Java case here used to
exercise a recipe matching one harvested entry in 51. The framework decides the install
commands, not just the probe: a JUnit 5 warm-up in a JUnit 4 project fails `test-compile` with
`cannot find symbol: class Test` and no image is built at all.

Every case's ground truth includes the exact sink file/line and target callable, and
`test_corpus.py` asserts `detect_stack` identifies the right language, build system, and test
framework for each.

Every Python case is written so its exploit condition is observable **offline**: probes have no
egress, so the SSRF case is driven against a loopback listener the probe starts, and the XXE
case's entity points at a marker file under the sandbox temp dir. The XXE pair uses
stdlib `xml.sax` (`feature_external_ges` on/off) rather than a third-party parser so no case
needs a dependency beyond `pytest`.

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
add an entry to `manifest.json`. `tests/evals/test_corpus.py` checks the manifest stays consistent
with the code.
