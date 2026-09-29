---
name: build-gradle
description: Recipe for building a Gradle Java test environment in the sandbox. Use this when planning
  or repairing a build for a Gradle project.
metadata:
  owner: appsec
  version: 1.0.0
---

# Building Gradle targets

<!-- generated: activation criteria (scripts/restructure_skills.py) -->

## Use this skill when

- You are producing or repairing an EnvironmentSpec for a Gradle project.
- The repository declares build.gradle or build.gradle.kts.

## Do not use this skill when

- The project builds with Maven — use `build-maven`.
- The repository is not a JVM project.

## When another skill also applies

- `build-maven` also fires on the repositories that carry both a `build.gradle` and a `pom.xml`, and each skill's negative criteria send the reader to the other, so on their own the two deadlock. **That skill wins** when the module holding the finding's sink is the one Maven builds; use this skill when Gradle owns that module — it has a `build.gradle` of its own, or a root `settings.gradle` includes it. Deciding matters because the flag that lets a probe's markers out is different on each side (`-i` here, `-Dmaven.test.redirectTestOutputToFile=false` there), so a spec built from the wrong recipe runs a correct probe and records nothing.

<!-- /generated: activation criteria -->

- **Base image:** `gradle:8-jdk21` or an Eclipse Temurin image plus the repo's `./gradlew`.
- **JDK version: read `sourceCompatibility`, `targetCompatibility` or
  `JavaLanguageVersion.of(...)` and match the image to the oldest level declared**, exactly as
  build-maven describes. `gradle:8-jdk21` is the default, not the answer: a project declaring
  Java 8 needs `gradle:8-jdk11`. Note that in `gradle:8-jdk21` the `8` is Gradle's version and
  the `21` is the JDK — matching the wrong one silently builds against a JDK the project cannot
  compile under.
- **Install / compile:** prefer the wrapper: `./gradlew --no-daemon testClasses` to resolve
  dependencies and compile test sources. Use `--offline` on the probe run. The `test` task
  compiles its own inputs, so the probe written into the container at probe time is compiled
  there — unlike Maven, no extra phase is needed.
- **Which runner Gradle uses is decided by `build.gradle`, not by the classpath.** This is the
  opposite of Maven, where Surefire auto-detects from the test classpath, and it decides which
  probe to write: Gradle's `Test` task runs JUnit 4 unless the build declares
  `test { useJUnitPlatform() }`. Measured on Gradle 8.14.3: a jupiter probe in a project with
  jupiter on the classpath and no `useJUnitPlatform()` fails with `No tests found for given
  includes`, and a JUnit-4 probe in a project that *does* declare it fails the same way. You may
  not edit `build.gradle`, so read that line and write the probe the build can run — see
  test-junit4 / test-junit5.
- **test_command:** `./gradlew --no-daemon --offline --rerun-tasks -i test --tests '<fqcn>'`
  targeting the probe's fully-qualified class.
  - **`-i` (`--info`) is load-bearing.** Gradle's `Test` task forwards a test's standard streams
    only from the INFO log level up; at the default level `System.out.println` from a test is
    dropped, so the probe's `HARNESS_` markers never reach the harness and a correct probe is
    recorded as having reached nothing. The alternative is
    `testLogging.showStandardStreams = true` in `build.gradle` — which you may not edit, so use
    the flag.
  - A `--tests` pattern that matches nothing fails the build rather than passing vacuously,
    which is what you want: it names the mismatch instead of hiding it.
  - **`--rerun-tasks` is load-bearing too, and not only on a repair attempt.** Gradle's `test`
    task is incremental: with unchanged inputs it is reported `UP-TO-DATE`, no test runs, no
    marker is printed, and the build exits 0. Measured on Gradle 8.14.3 — the first run printed
    all three markers and the next two printed none, `> Task :test UP-TO-DATE` being the only
    difference. That is the silent shape the harness cannot diagnose, so make the run
    unconditional rather than hoping the inputs differ. `cleanTest test` says the same thing.
- **Registries:** honor `settings.gradle`/`init.gradle` repositories the project declares;
  supply credentials via BuildKit secrets.
- **Partial builds:** target a subproject: `./gradlew --rerun-tasks -i :<subproject>:test --tests '<fqcn>'`.

<!-- generated: constraints (scripts/restructure_skills.py) -->

## Safety constraints

- Install as the non-root sandbox user with `HOME=/work/home`; never `sudo` or run as root.
- Use only the package indexes and registries the repository itself declares.
- Build-time network access is limited to the registry allowlist; probe time has none at all.

## Completion criteria

- The spec names a base image from the allowlisted registries.
- Install commands come from the repository's own manifests.
- The test runner itself is installed, not merely assumed present.
- No install command swallows its own failure (`|| true`, `|| :`, `; true`). A dependency install that reports success when it failed surfaces only at probe time, where probe repair cannot fix it and build repair never sees it.
- `test_command` names the probe's test *class* in its selector (`-Dtest=HarnessProbeTest`, `--tests '*HarnessProbeTest'`) — not a file path, which these runners do not accept. The probe's class name must therefore match the selector.
- `test_command` runs at the INFO log level (`-i`): Gradle's `Test` task forwards a test's standard streams only from INFO up, so at the default level the probe's markers are dropped and a correct probe is recorded as having reached nothing.
- `test_command` makes the run unconditional (`--rerun-tasks`, or `cleanTest test`). Gradle's `test` task is incremental, so with unchanged inputs it is reported `UP-TO-DATE`: no test runs, no marker is printed, and the build still exits 0. Measured on Gradle 8.14.3, where the first run printed all three markers and the next two printed none.
- The probe is written in the framework `build.gradle` declares, not the one on the classpath: Gradle runs JUnit 4 unless the build says `test { useJUnitPlatform() }`, and a mismatch fails with `No tests found for given includes` (measured). Unlike Surefire, Gradle does not auto-detect, and you may not edit the build file.

<!-- /generated: constraints -->
