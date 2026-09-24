---
name: partial-build
description: "Tactics for building only the sub-unit that contains the finding when a full build fails."
---

# Partial builds

When a full build cannot be made to work within budget, build only the smallest unit that
contains the file under investigation and can run one unit test. Set `scope: partial` and
`module_path` to that unit's directory.

- **Maven:** `mvn -q -B -pl <module> -am -DskipTests test-compile`; test with `-pl <module>`.
  `-am` also builds the modules it depends on.
- **Gradle:** target the owning subproject: `:<subproject>:testClasses` then
  `:<subproject>:test --tests '<fqcn>'`.
- **Python:** install just the finding's package/extra and pytest, skipping optional heavy
  extras; run the single probe file. If an unrelated import at module import time breaks
  collection, add a minimal conftest or stub for that dependency — never stub the code under
  test.
- **Node:** install and test within the one workspace package that owns the file.
- **Perl:** install deps for the one module directory.

Rules: only stub or exclude dependencies that are **unrelated** to the sink; the sink and its
data path must remain real. Record why the unit was chosen in `rationale`. A partial
environment still produces real probe evidence; the verdict is tagged so evals can compare
partial vs full accuracy.
