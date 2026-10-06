# Independent paired corpus

The unchanged starter corpus contains 36 small Python, Java, JavaScript and Perl cases.
`manifest.json` pairs findings with scoring truth. Only the finding and repository snapshot
are submitted to the investigator; expected verdicts stay outside its sandbox.

## Cases (36 total)

Each case name is `[<lang>-]<cwe>-<variant>` (Python cases are unprefixed). The manifest is checked by `tests/evals/test_cohort.py`.

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
CommonJS and ESM/TypeScript; Perl includes Test::More and Test2::V0. The agent must inspect
and handle the actual build configuration through skills and tools.

`external/` retains historical harvested datasets and attribution. They are not accepted
by this evaluator: they require remote-source and test-masking controls before use. The
old stage-specific harvesting and scoring commands have been removed. Do not interpret
this small seeded corpus as production-scale or independently held-out quality evidence.
