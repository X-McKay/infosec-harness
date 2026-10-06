# Independent paired corpus

The seeded corpus contains 82 small Python, Java, JavaScript, Perl and C cases: the 36-case
starter set followed by 46 cases for the skill-coverage CWE classes. `manifest.json` pairs
findings with scoring truth. Only the finding and repository snapshot are submitted to the
investigator; expected verdicts stay outside its sandbox.

## Cases (82 total)

Each case name is `[<lang>-]<cwe>-<variant>` (Python cases are unprefixed). The manifest is checked by `tests/evals/test_cohort.py`.

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

The C fixtures ship a `make test` target whose binary runs the same in-bounds and bounded
boundary inputs against both variants: the vulnerable build aborts under AddressSanitizer
and the fixed build exits 0. The `node --test` fixtures need no installed packages.


## Run

Configure the worker's approved local roots to include this directory, then run:

```bash
./dev eval [--settings settings.json]   # owned worker; .harness/reports/model-<UTC time>.json
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
