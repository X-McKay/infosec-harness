# Independent paired corpus

The seeded corpus contains 82 small Python, Java, JavaScript, Perl and C cases: the 36-case
starter set followed by 46 cases for the skill-coverage CWE classes. `manifest.json` pairs
findings with scoring truth. Only the finding (title, description, file path, CWE) and the
variant's repository snapshot are submitted to the investigator; case names and expected
verdicts stay outside its sandbox.

## Keeping labels out of agent inputs

Everything the investigator can read must be the same kind of evidence for both variants of a
pair, so that a correct verdict comes from analysing the code and not from reading the answer:

- Variant directories are named `a` and `b`. Which one is exploitable was assigned per topic by
  a deterministic shuffle and is recorded only in `manifest.json` and in the answer key below.
- Fixture sources, tests, package metadata and file names carry no verdict words (`vulnerable`,
  `fixed`, `safe`, `insecure`, `exploit`, `patched`, `mitigated`, `sanitized` and their
  variants) and no comment explaining the weakness or the defence. A comment may say what the
  code does, in the same words in both variants.
- Both findings of a pair share one title and one description, true of both variants; they
  differ only in `repo_url` and, where the code differs, `start_line`.

- Fixtures ship no tests. A test that runs the code must assert what that variant does, which
  is the answer, so every fixture test lives outside the snapshot under `verification/` (see
  the maintainers' section). A fixture's test directory holds only a `.gitkeep`; the one
  exception is `python/queryhelper`, whose finding is about the test helper itself.

`tests/evals/test_corpus_hygiene.py` enforces these rules.

## Cases (82 total)

Each case name is `[<lang>-]<cwe>-<variant>` (Python cases are unprefixed). Case names are
maintainer labels and never reach the investigator. The manifest is checked by
`tests/evals/test_cohort.py` and `tests/evals/test_corpus_hygiene.py`.

| Language | Cases |
|---|---|
| python | 42 |
| java | 6 |
| javascript | 18 |
| perl | 12 |
| c | 4 |

Starter set (36):

| Cases | Language | CWE | Toolchain |
|---|---|---|---|
| `sqli-vulnerable`, `sqli-fixed` | python | CWE-89 | pip / pytest |
| `cmdi-vulnerable`, `cmdi-fixed` | python | CWE-78 | pip / pytest |
| `pathtraversal-vulnerable`, `pathtraversal-fixed` | python | CWE-22 | pip / pytest |
| `xss-vulnerable`, `xss-fixed` | python | CWE-79 | pip / pytest |
| `codeinjection-vulnerable`, `codeinjection-fixed` | python | CWE-94 | pip / pytest |
| `deserialization-vulnerable`, `deserialization-fixed` | python | CWE-502 | pip / pytest |
| `xxe-vulnerable`, `xxe-fixed` | python | CWE-611 | pip / pytest |
| `ssrf-vulnerable`, `ssrf-fixed` | python | CWE-918 | pip / pytest |
| `unreachable` | python | CWE-89 | pip / pytest |
| `testonly` | python | CWE-89 | pip / pytest |
| `java-sqli-vulnerable`, `java-sqli-fixed` | java | CWE-89 | maven / junit5, release 17 |
| `java-cmdi-vulnerable`, `java-cmdi-fixed` | java | CWE-78 | maven / junit5, release 17 |
| `java-xxe-vulnerable`, `java-xxe-fixed` | java | CWE-611 | maven / **junit4**, source 1.7 |
| `javascript-cmdi-vulnerable`, `javascript-cmdi-fixed` | javascript | CWE-78 | npm / jest, CommonJS |
| `javascript-xss-vulnerable`, `javascript-xss-fixed` | javascript | CWE-79 | npm / jest, CommonJS |
| `javascript-xssesm-vulnerable`, `javascript-xssesm-fixed` | javascript | CWE-79 | npm / vitest, ESM + TypeScript |
| `perl-sqli-vulnerable`, `perl-sqli-fixed` | perl | CWE-89 | cpanm / Test::More |
| `perl-cmdi-vulnerable`, `perl-cmdi-fixed` | perl | CWE-78 | cpanm / Test::More |
| `perl-xss-vulnerable`, `perl-xss-fixed` | perl | CWE-79 | Module::Build / Test2::V0 |

Skill-coverage additions (46), in manifest order:

| Cases | Language | CWE | Toolchain |
|---|---|---|---|
| `javascript-prototypepollution-vulnerable`, `-fixed` | javascript | CWE-1321 | npm / jest, CommonJS |
| `massassignment-vulnerable`, `massassignment-fixed` | python | CWE-915 | pip / pytest |
| `errorexposure-vulnerable`, `errorexposure-fixed` | python | CWE-209 | pip / pytest |
| `insecuretemp-vulnerable`, `insecuretemp-fixed` | python | CWE-377 | pip / pytest |
| `javascript-cors-vulnerable`, `javascript-cors-fixed` | javascript | CWE-942 | npm / jest, CommonJS |
| `perl-permissions-vulnerable`, `perl-permissions-fixed` | perl | CWE-732 | cpanm / Test::More |
| `openredirect-vulnerable`, `openredirect-fixed` | python | CWE-601 | pip / pytest |
| `formulainjection-vulnerable`, `formulainjection-fixed` | python | CWE-1236 | pip / pytest |
| `fileinclusion-vulnerable`, `fileinclusion-fixed` | python | CWE-98 | pip / pytest |
| `perl-responsesplitting-vulnerable`, `-fixed` | perl | CWE-113 | cpanm / Test::More |
| `javascript-arginjection-vulnerable`, `-fixed` | javascript | CWE-77 | npm / jest, CommonJS |
| `idor-vulnerable`, `idor-fixed` | python | CWE-862 | pip / pytest |
| `jwtnone-vulnerable`, `jwtnone-fixed` | python | CWE-347 | pip / pytest |
| `pwhash-vulnerable`, `pwhash-fixed` | python | CWE-327 | pip / pytest |
| `javascript-sessionrandom-vulnerable`, `-fixed` | javascript | CWE-330 | npm / built-in `node --test`, CommonJS |
| `javascript-sessionfix-vulnerable`, `-fixed` | javascript | CWE-384 | npm / built-in `node --test`, CommonJS |
| `perl-adminpw-vulnerable`, `perl-adminpw-fixed` | perl | CWE-798 | cpanm / Test::More |
| `c-stackoverflow-vulnerable`, `c-stackoverflow-fixed` | c | CWE-787 | make / gcc, AddressSanitizer test binary |
| `c-intoverflow-vulnerable`, `c-intoverflow-fixed` | c | CWE-190 | make / gcc, AddressSanitizer test binary |
| `redos-vulnerable`, `redos-fixed` | python | CWE-1333 | pip / pytest |
| `javascript-zipbomb-vulnerable`, `-fixed` | javascript | CWE-400 | npm / built-in `node --test`, CommonJS |
| `toctou-vulnerable`, `toctou-fixed` | python | CWE-362 | pip / pytest |
| `nullderef-vulnerable`, `nullderef-fixed` | python | CWE-476 | pip / pytest |

The C fixtures ship a `make test` target; its test program is in `verification/` with the
other fixture tests. The `node --test` fixtures need no installed packages.

## Maintainers only

Nothing in this section may be copied into a finding, prompt, skill, fixture or anything else
an agent reads.

### Fixture verification

`verification/<lang>/<topic>/<a|b>/` holds the tests for that fixture, at the paths they would
have inside it. They never enter a snapshot. To check that every fixture still behaves as its
truth says:

```bash
.venv/bin/python scripts/corpus_verify.py [--node PATH] [--python PATH]
```

For each verification directory the script copies the fixture to a temporary directory,
overlays the tests and runs `python -m pytest`, the pinned `node --test`, `prove -l t` or
`make test CC=cc`, printing one line per fixture and exiting non-zero on any failure. Every
runner must pass except `make test` on a C variant whose truth is `potentially_exploitable`,
which must abort with an AddressSanitizer report. `--node` defaults to the pinned install under
`.harness/mise`; `--python` defaults to the interpreter running the script and needs pytest.
Java fixtures have no verification tests.

On 2026-10-06 the investigator found a residual defect in a fixed variant: `nullderef-fixed`
still dereferenced `None` when the payload was the JSON literal `null`, so its
`potentially_exploitable` verdict was right. The ground truth was corrected (the fixture now
rejects a non-object payload, its sink line moved to 12, and its verification test covers
non-object payloads) rather than the verdict.

In cohort 13 (2026-10-06, main `b1256fc`) the investigator found that `openredirect-fixed` was
still an open redirect: `/\evil.v8k2m9.example/` has no scheme, no netloc and one leading
slash, so it passed the relative-path guard, and browsers read the backslash as `/`, giving the
external `//evil.v8k2m9.example/`. Its `potentially_exploitable` verdict was right. The fixture
now refuses control characters and treats `\` as `/` before the slash checks (returning the
normalised path); the vulnerable variant is unchanged, the fixed variant's sink line moved from
22 to 25, and both variants gained verification tests (the fixed one covers backslash,
control-character, protocol-relative and absolute payloads).

### Answer key

**This table is the answer key. Never copy it, or any mapping from a directory to a verdict,
into a finding, prompt, skill, fixture or anything else an agent reads.** Directories are
relative to `eval-corpus/`. Three topic directories are named for their subject rather than
their case: `insecuretemp-*` live under `python/tempfile`, `unreachable` under
`python/healthcheck` and `testonly` under `python/queryhelper`.

| Case | Directory | Expected verdict |
|---|---|---|
| `sqli-vulnerable` | `python/sqli/a` | `potentially_exploitable` |
| `sqli-fixed` | `python/sqli/b` | `likely_not_exploitable` |
| `cmdi-vulnerable` | `python/cmdi/b` | `potentially_exploitable` |
| `cmdi-fixed` | `python/cmdi/a` | `likely_not_exploitable` |
| `pathtraversal-vulnerable` | `python/pathtraversal/a` | `potentially_exploitable` |
| `pathtraversal-fixed` | `python/pathtraversal/b` | `likely_not_exploitable` |
| `xss-vulnerable` | `python/xss/b` | `potentially_exploitable` |
| `xss-fixed` | `python/xss/a` | `likely_not_exploitable` |
| `codeinjection-vulnerable` | `python/codeinjection/b` | `potentially_exploitable` |
| `codeinjection-fixed` | `python/codeinjection/a` | `likely_not_exploitable` |
| `deserialization-vulnerable` | `python/deserialization/a` | `potentially_exploitable` |
| `deserialization-fixed` | `python/deserialization/b` | `likely_not_exploitable` |
| `xxe-vulnerable` | `python/xxe/b` | `potentially_exploitable` |
| `xxe-fixed` | `python/xxe/a` | `likely_not_exploitable` |
| `ssrf-vulnerable` | `python/ssrf/a` | `potentially_exploitable` |
| `ssrf-fixed` | `python/ssrf/b` | `likely_not_exploitable` |
| `unreachable` | `python/healthcheck/a` | `likely_not_exploitable` |
| `testonly` | `python/queryhelper/a` | `likely_not_exploitable` |
| `java-sqli-vulnerable` | `java/sqli/b` | `potentially_exploitable` |
| `java-sqli-fixed` | `java/sqli/a` | `likely_not_exploitable` |
| `java-cmdi-vulnerable` | `java/cmdi/b` | `potentially_exploitable` |
| `java-cmdi-fixed` | `java/cmdi/a` | `likely_not_exploitable` |
| `java-xxe-vulnerable` | `java/xxe/b` | `potentially_exploitable` |
| `java-xxe-fixed` | `java/xxe/a` | `likely_not_exploitable` |
| `javascript-cmdi-vulnerable` | `javascript/cmdi/b` | `potentially_exploitable` |
| `javascript-cmdi-fixed` | `javascript/cmdi/a` | `likely_not_exploitable` |
| `javascript-xss-vulnerable` | `javascript/xss/a` | `potentially_exploitable` |
| `javascript-xss-fixed` | `javascript/xss/b` | `likely_not_exploitable` |
| `perl-sqli-vulnerable` | `perl/sqli/a` | `potentially_exploitable` |
| `perl-sqli-fixed` | `perl/sqli/b` | `likely_not_exploitable` |
| `perl-cmdi-vulnerable` | `perl/cmdi/b` | `potentially_exploitable` |
| `perl-cmdi-fixed` | `perl/cmdi/a` | `likely_not_exploitable` |
| `javascript-xssesm-vulnerable` | `javascript/xssesm/a` | `potentially_exploitable` |
| `javascript-xssesm-fixed` | `javascript/xssesm/b` | `likely_not_exploitable` |
| `perl-xss-vulnerable` | `perl/xss/b` | `potentially_exploitable` |
| `perl-xss-fixed` | `perl/xss/a` | `likely_not_exploitable` |
| `javascript-prototypepollution-vulnerable` | `javascript/prototypepollution/a` | `potentially_exploitable` |
| `javascript-prototypepollution-fixed` | `javascript/prototypepollution/b` | `likely_not_exploitable` |
| `massassignment-vulnerable` | `python/massassignment/b` | `potentially_exploitable` |
| `massassignment-fixed` | `python/massassignment/a` | `likely_not_exploitable` |
| `errorexposure-vulnerable` | `python/errorexposure/a` | `potentially_exploitable` |
| `errorexposure-fixed` | `python/errorexposure/b` | `likely_not_exploitable` |
| `insecuretemp-vulnerable` | `python/tempfile/b` | `potentially_exploitable` |
| `insecuretemp-fixed` | `python/tempfile/a` | `likely_not_exploitable` |
| `javascript-cors-vulnerable` | `javascript/cors/b` | `potentially_exploitable` |
| `javascript-cors-fixed` | `javascript/cors/a` | `likely_not_exploitable` |
| `perl-permissions-vulnerable` | `perl/permissions/a` | `potentially_exploitable` |
| `perl-permissions-fixed` | `perl/permissions/b` | `likely_not_exploitable` |
| `openredirect-vulnerable` | `python/openredirect/a` | `potentially_exploitable` |
| `openredirect-fixed` | `python/openredirect/b` | `likely_not_exploitable` |
| `formulainjection-vulnerable` | `python/formulainjection/a` | `potentially_exploitable` |
| `formulainjection-fixed` | `python/formulainjection/b` | `likely_not_exploitable` |
| `fileinclusion-vulnerable` | `python/fileinclusion/b` | `potentially_exploitable` |
| `fileinclusion-fixed` | `python/fileinclusion/a` | `likely_not_exploitable` |
| `perl-responsesplitting-vulnerable` | `perl/responsesplitting/a` | `potentially_exploitable` |
| `perl-responsesplitting-fixed` | `perl/responsesplitting/b` | `likely_not_exploitable` |
| `javascript-arginjection-vulnerable` | `javascript/arginjection/a` | `potentially_exploitable` |
| `javascript-arginjection-fixed` | `javascript/arginjection/b` | `likely_not_exploitable` |
| `idor-vulnerable` | `python/idor/b` | `potentially_exploitable` |
| `idor-fixed` | `python/idor/a` | `likely_not_exploitable` |
| `jwtnone-vulnerable` | `python/jwtnone/a` | `potentially_exploitable` |
| `jwtnone-fixed` | `python/jwtnone/b` | `likely_not_exploitable` |
| `pwhash-vulnerable` | `python/pwhash/a` | `potentially_exploitable` |
| `pwhash-fixed` | `python/pwhash/b` | `likely_not_exploitable` |
| `javascript-sessionrandom-vulnerable` | `javascript/sessionrandom/a` | `potentially_exploitable` |
| `javascript-sessionrandom-fixed` | `javascript/sessionrandom/b` | `likely_not_exploitable` |
| `javascript-sessionfix-vulnerable` | `javascript/sessionfix/a` | `potentially_exploitable` |
| `javascript-sessionfix-fixed` | `javascript/sessionfix/b` | `likely_not_exploitable` |
| `perl-adminpw-vulnerable` | `perl/adminpw/b` | `potentially_exploitable` |
| `perl-adminpw-fixed` | `perl/adminpw/a` | `likely_not_exploitable` |
| `c-stackoverflow-vulnerable` | `c/stackoverflow/a` | `potentially_exploitable` |
| `c-stackoverflow-fixed` | `c/stackoverflow/b` | `likely_not_exploitable` |
| `c-intoverflow-vulnerable` | `c/intoverflow/a` | `potentially_exploitable` |
| `c-intoverflow-fixed` | `c/intoverflow/b` | `likely_not_exploitable` |
| `redos-vulnerable` | `python/redos/b` | `potentially_exploitable` |
| `redos-fixed` | `python/redos/a` | `likely_not_exploitable` |
| `javascript-zipbomb-vulnerable` | `javascript/zipbomb/b` | `potentially_exploitable` |
| `javascript-zipbomb-fixed` | `javascript/zipbomb/a` | `likely_not_exploitable` |
| `toctou-vulnerable` | `python/toctou/b` | `potentially_exploitable` |
| `toctou-fixed` | `python/toctou/a` | `likely_not_exploitable` |
| `nullderef-vulnerable` | `python/nullderef/a` | `potentially_exploitable` |
| `nullderef-fixed` | `python/nullderef/b` | `likely_not_exploitable` |


## Run

The cohort resolves each fixture path against the checkout it runs from, so the worker's
approved local roots must include that checkout's `eval-corpus/`. Without `--settings`,
`./dev` sets exactly that root; a settings file must name it in `local_repo_roots`. Then run:

```bash
./dev eval [--settings settings.json] [--parallel N]   # .harness/reports/model-<UTC time>.json
```

`./dev eval` starts its own worker on a fresh task queue with the same configuration. A bare
`harness eval --allow-inference` without `--owned-worker` instead needs a separately started
worker with identical settings. See
[qualification and evaluation](../deploy/openshell/README.md#qualification-and-evaluation).

The complete corpus runs through the normal Temporal/OpenShell investigation path, once
per case. The report retains failures and unstarted cases. The packaged release policy
(`src/infosec_harness/evals/release-policy.yaml`) requires at least 75% correct verdicts and
zero unsafe negative verdicts. Inconclusive is not a
correct negative. Native runtime and live model evidence must be qualified independently.

The two unpaired Python cases (`unreachable`, `testonly`) exercise claims whose context
should prevent exploitation. The SSRF and XXE cases can be tested offline with local
listeners and files. Java includes JUnit 4/5 and old source levels; JavaScript includes
CommonJS, ESM/TypeScript and the built-in `node --test` runner; Perl includes Test::More and
Test2::V0; C uses make and gcc. The agent must inspect and handle the actual build
configuration through skills and tools.

`external/` retains historical harvested datasets and attribution. They are not accepted
by this evaluator: they require remote-source and test-masking controls before use. The
old stage-specific harvesting and scoring commands have been removed. Do not interpret
this small seeded corpus as production-scale or independently held-out quality evidence.
