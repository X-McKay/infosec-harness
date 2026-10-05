---
name: partial-build
description: Tactics for building only the sub-unit that contains the finding. Use this when a full
  build has exhausted its repair budget.
metadata:
  owner: appsec
  version: 1.0.1
---

# Partial builds

## Use this skill when

- The full build has failed its repair budget and a narrower scope is the remaining option.
- The failures are in dependencies unrelated to the finding's module.

## Do not use this skill when

- The full build has not yet exhausted its repairs — repair it instead.
- The failure is in the sink's own module or its real dependencies: narrowing there would stub out the code under test.

## Procedure

When a full build cannot be made to work within budget, build only the smallest unit that
contains the file under investigation and can run one unit test. Set `scope: partial` and
`module_path` to that unit's directory.

- **Maven:** `mvn -B -Dmaven.repo.local=/opt/home/.m2/repository -pl <module> -am -DskipTests
  test-compile`; test with `-pl <module>`. The repo-local flag goes on *every* install
  command (see build-maven): build time writes under `/opt/home`, probe time reads the
  tmpfs copy under `/work/home`, and a narrowed spec is where it is easiest to drop.
  `-am` also builds the modules it depends on.
- **Gradle:** target the owning subproject: `:<subproject>:testClasses` then
  `:<subproject>:test --tests '*<ProbeClassName>'`.
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

## Safety constraints

- Install as the non-root sandbox user with `HOME=/work/home`; never `sudo` or run as root.
- Use only the package indexes and registries the repository itself declares.
- Build-time network access is limited to the registry allowlist; probe time has none at all.
- Only stub or exclude dependencies unrelated to the sink. Never stub the code under test, its module, or anything on the path from source to sink.

## Completion criteria

- The spec names a base image from the allowlisted registries.
- Install commands come from the repository's own manifests.
- The test runner itself is installed, not merely assumed present.
- No install command swallows its own failure (`|| true`, `|| :`, `; true`). A dependency install that reports success when it failed surfaces only at probe time, where probe repair cannot fix it and build repair never sees it.
- `scope` is `partial` and `module_path` names the unit that was built.
