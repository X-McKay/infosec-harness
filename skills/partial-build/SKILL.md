---
name: partial-build
description: Tactics for building only the sub-unit that contains the finding. Use this when a full
  build has exhausted its repair budget.
metadata:
  owner: appsec
  version: 1.0.0
---

# Partial builds

## Use this skill when

- The full build has failed its repair budget and a narrower scope is the remaining option.
- The failures are in dependencies unrelated to the finding's module.

## Do not use this skill when

- The full build has not yet exhausted its repairs — repair it instead.
- The failure is in the sink's own module or its real dependencies: narrowing there would stub out the code under test.



## Safety constraints

- Install as the non-root sandbox user with `HOME=/work/home`; never `sudo` or run as root.
- Use only the package indexes and registries the repository itself declares.
- Build-time network access is limited to the registry allowlist; probe time has none at all.
- Only stub or exclude dependencies unrelated to the sink. Never stub the code under test, its module, or anything on the path from source to sink.

## Completion criteria

- The spec names a base image from the allowlisted registries.
- Install commands come from the repository's own manifests.
- `test_command` contains the `{test_file}` placeholder and runs a single test file.
- The test runner itself is installed, not merely assumed present.
- `scope` is `partial` and `module_path` names the unit that was built.
