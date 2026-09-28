---
name: build-maven
description: Recipe for building a Maven Java test environment in the sandbox. Use this when planning
  or repairing a build for a pom.xml project.
metadata:
  owner: appsec
  version: 1.0.0
---

# Building Maven targets

<!-- generated: activation criteria (scripts/restructure_skills.py) -->

## Use this skill when

- You are producing or repairing an EnvironmentSpec for a Maven project.
- The repository declares a pom.xml.

## Do not use this skill when

- The project builds with Gradle — use `build-gradle`.
- The repository is not a JVM project.

<!-- /generated: activation criteria -->

- **Base image:** `maven:3.9-eclipse-temurin-21` (drop to `-17` if the project targets 17).
- **Install / compile:** `mvn -q -B -DskipTests test-compile` to pull dependencies and compile
  main + test sources. Use `-s <settings.xml>` when the repo ships one (private registries,
  mirrors); pass registry credentials as BuildKit secrets, never in the image.
- **test_command:** run one test class: `mvn -q -B -o test -Dtest=<ProbeClassName>`
  (`-o` offline so the probe run needs no network; everything is already resolved at build).
  Match `<ProbeClassName>` to the probe's class (see test-junit5).
- **Partial builds:** `mvn -q -B -pl <module> -am -DskipTests test-compile`, then
  `-pl <module>` on the test command (see partial-build).

<!-- generated: constraints (scripts/restructure_skills.py) -->

## Safety constraints

- Install as the non-root sandbox user with `HOME=/work/home`; never `sudo` or run as root.
- Use only the package indexes and registries the repository itself declares.
- Build-time network access is limited to the registry allowlist; probe time has none at all.

## Completion criteria

- The spec names a base image from the allowlisted registries.
- Install commands come from the repository's own manifests.
- `test_command` contains the literal `{test_file}` placeholder — never a hardcoded test path. The harness writes the probe to the path its author chose and substitutes it here; a hardcoded path runs a file that does not exist and no test executes.
- A pytest command disables output capture with `-s`, or the probe's markers are buffered away and a correct probe is recorded as having reached nothing.
- The test runner itself is installed, not merely assumed present.

<!-- /generated: constraints -->
