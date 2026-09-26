---
name: build-gradle
description: Recipe for building a Gradle Java test environment in the sandbox. Use this when planning
  or repairing a build for a Gradle project.
metadata:
  owner: appsec
  version: 1.0.0
---

# Building Gradle targets

## Use this skill when

- You are producing or repairing an EnvironmentSpec for a Gradle project.
- The repository declares build.gradle or build.gradle.kts.

## Do not use this skill when

- The project builds with Maven — use `build-maven`.
- The repository is not a JVM project.



## Safety constraints

- Install as the non-root sandbox user with `HOME=/work/home`; never `sudo` or run as root.
- Use only the package indexes and registries the repository itself declares.
- Build-time network access is limited to the registry allowlist; probe time has none at all.

## Completion criteria

- The spec names a base image from the allowlisted registries.
- Install commands come from the repository's own manifests.
- `test_command` contains the `{test_file}` placeholder and runs a single test file.
- The test runner itself is installed, not merely assumed present.
