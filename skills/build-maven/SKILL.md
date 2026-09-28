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

- **Set the local repository explicitly, to two different paths.** Verified against the corpus:
  `-Dmaven.repo.local=/opt/home/.m2/repository` on every install command, and
  `-Dmaven.repo.local=/work/home/.m2/repository` on the test command. Maven takes its local
  repository from the JVM's `user.home`, and the sandbox user has no passwd entry, so that
  resolves to `/root` and the build dies with `mkdir: cannot create directory '/root':
  Permission denied` before resolving anything. The two paths differ because the image is built
  with `HOME=/opt/home` and the probe runs from a `/work/home` copy of it.
- **Warm Surefire by *running* a test, not by invoking the plugin.** This is the difference
  between a Java target that scores and one that scores nothing, and it is not optional.
  Surefire resolves its **provider** lazily — at test-execution time, from the JUnit version it
  finds on the test classpath — not during dependency resolution. So a warm-up that invokes the
  pinned goal with nothing to run (`-DfailIfNoTests=false`, against a project whose `src/test/java`
  is empty) downloads the plugin and every one of its own dependencies, reports BUILD SUCCESS,
  and stops short of the provider. The offline probe then dies with
  `org.apache.maven.surefire:surefire-junit-platform:jar:3.2.5 (absent): Cannot access central
  … in offline mode and the artifact … has not been downloaded from it before` — a build that
  exits 0 and a probe that reports nothing, which is the shape neither build repair (it never
  sees the failure) nor probe repair (the probe is correct) can act on. Give the warm-up a test
  to run: write a throwaway JUnit 5 class, run the pinned goal against it, and delete it, all in
  one install command. Verified against the whole Java corpus, in a `--network=none` probe
  container.
- **Do not try to pin the provider instead.** Adding
  `dependency:get -Dartifact=org.apache.maven.surefire:surefire-junit-platform:3.2.5` looks like
  the tidier fix and is measurably not one: the offline run then fails on the *next* artifact,
  `org.junit.platform:junit-platform-launcher:jar:1.10.2`, whose version Surefire derives from
  the project's own JUnit and which no fixed artifact list can predict (the real run fetched two
  launcher versions, 1.9.3 and 1.10.2). `dependency:resolve-plugins` is worse still: it resolves
  the plugins in the effective pom, which means Surefire 2.12.4, and leaves even the pinned 3.2.5
  plugin absent. And **dropping `-o` is not a fallback** — the probe container has no network at
  all, so an online Maven just fails later and slower.
- **Base image:** `maven:3.9-eclipse-temurin-21` (drop to `-17` if the project targets 17).
- **Never `-q`.** Use `-B` for non-interactive batch output instead. Maven relays the forked test
  JVM's stdout through its own logger at INFO level, so `-q` raises the threshold above the
  probe's `HARNESS_` markers: the probe runs, passes, and is recorded as having reached nothing.
  This is the Maven form of running pytest without `-s`.
- **Install / compile — two commands, the second one exactly this shape:**

  ```
  mvn -B -Dmaven.repo.local=/opt/home/.m2/repository -DskipTests test-compile
  mkdir -p src/test/java && echo 'import org.junit.jupiter.api.Test; class HarnessWarmupTest { @Test void warm() {} }' > src/test/java/HarnessWarmupTest.java && mvn -B -Dmaven.repo.local=/opt/home/.m2/repository test-compile org.apache.maven.plugins:maven-surefire-plugin:3.2.5:test -Dtest=HarnessWarmupTest && rm -f src/test/java/HarnessWarmupTest.java target/test-classes/HarnessWarmupTest.class
  ```

  The first pulls dependencies and compiles main + test sources. The second is the provider
  warm-up from above: it really executes a test, which is the only thing that makes Surefire
  resolve `surefire-junit-platform` and the matching `junit-platform-launcher` into the local
  repository, so the probe run can be offline. Every part of it earns its place:

  - **One line, `echo` and not a heredoc.** Each install command is rendered as a single
    Dockerfile `RUN`, so a multi-line heredoc does not survive; the warm-up class is therefore
    one line of Java, which javac accepts.
  - **`-Dtest=HarnessWarmupTest`.** The selector confines the warm-up to the throwaway class, so
    the build does not run — or fail on — the project's own suite.
  - **No `-DfailIfNoTests=false`.** That flag is what let the old warm-up pass while running
    nothing. Leaving it off means a warm-up that silently stopped working fails the build, where
    build repair can see it.
  - **The `rm -f` at the end.** The class has done its job once the repository is warm; leaving it
    in the image would ship a stray test into `/work/repo` for the probe run to recompile.

  Use `-s <settings.xml>` when the repo ships one (private registries, mirrors); pass registry
  credentials as BuildKit secrets, never in the image.
- **test_command — pin Surefire, and compile the probe:**

  ```
  mvn -B -o test-compile \
      org.apache.maven.plugins:maven-surefire-plugin:3.2.5:test \
      -Dtest=<ProbeClassName> -Dmaven.test.redirectTestOutputToFile=false
  ```

  Every part of that is load-bearing:

  - **`test-compile`, not `test`.** The probe file is written into the container at probe time,
    *after* the image is built, so the command has to compile it. But the `test` phase (and
    `verify`, `package`, `install`) also triggers the pom's own Surefire execution, which is
    the next problem — so compile with `test-compile` and invoke the test goal explicitly.
  - **The fully-qualified, version-pinned goal.** Maven 3.x binds
    `maven-surefire-plugin:2.12.4` to the `test` phase by default, and 2.12.4 has **no JUnit
    Platform provider**: a JUnit 5 probe is never discovered, `-Dtest=<Class>` matches nothing,
    and the build fails with "No tests were executed" — a nonzero exit and no markers, which
    reads downstream as a defective probe forever. A plugin version bound to a phase cannot be
    overridden from the command line, and you may not edit the repository's `pom.xml`, so
    naming the goal with its version is the only fix available to an EnvironmentSpec. Use 3.2.5
    unless the pom already pins something newer.
  - **`-Dmaven.test.redirectTestOutputToFile=false`.** A pom that turns the redirect on sends
    the markers to `target/surefire-reports/*-output.txt`; the harness reads stdout only.
  - **`-o`** keeps the probe run offline, which it is anyway — probe containers have no network.
    It only works because the install step above warmed the plugin *and* the provider by running
    a test; with the plugin alone, this is the command that fails on
    `surefire-junit-platform:jar:3.2.5 (absent)`.

  Match `<ProbeClassName>` to the probe's class (see test-junit5).
- **Partial builds:** `mvn -B -pl <module> -am -DskipTests test-compile`, then `-pl <module>` on
  the test command (see partial-build).

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
- `test_command` compiles the probe (`test-compile`) and then invokes a version-pinned Surefire goal (`org.apache.maven.plugins:maven-surefire-plugin:3.2.5:test`) rather than the `test` phase: Maven 3.x binds Surefire 2.12.4, which has no JUnit Platform provider and so discovers no JUnit 5 test at all.
- `test_command` uses `-B` and never `-q`, and passes `-Dmaven.test.redirectTestOutputToFile=false`, so the probe's markers reach stdout.
- An install command warms Surefire's JUnit Platform provider by *running* a test — a throwaway JUnit 5 class written, run under the pinned goal with `-Dtest=`, and deleted — and not merely by invoking the plugin with `-DfailIfNoTests=false`. Surefire resolves the provider at test-execution time, so a warm-up that runs no test fetches the plugin and none of the provider, and the offline probe fails on `surefire-junit-platform:jar:… (absent)`.

<!-- /generated: constraints -->
