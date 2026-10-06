---
name: lang-java
description: 'Conventions for reading Java repositories: Maven and Gradle layout, entry points, and
  JUnit tests. Use this when the repository is primarily Java.'
metadata:
  owner: appsec
  version: 1.1.0
---

# Java repositories

## Use this skill when

- The repository's primary language is Java or Kotlin on the JVM.
- You need to locate its module layout, entry points, or tests.

## Do not use this skill when

- The repository is primarily another language.
- You are planning the build itself — use `environment`.

## Procedure

- **Manifests:** `pom.xml` (Maven), `build.gradle`/`build.gradle.kts` (Gradle). Multi-module
  builds list `<modules>` / `include`.
- **Layout:** `src/main/java/...` for code, `src/test/java/...` for tests; package = directory.
- **Entry points:** servlets and Spring `@RestController`/`@RequestMapping`, `main` methods,
  message listeners.
- **Tests:** JUnit 5 (`org.junit.jupiter`) or 4; classes `*Test`/`*Tests`, methods annotated
  `@Test`.
- **Sinks to note:** `Statement.executeQuery` with concatenation, `Runtime.exec`/`ProcessBuilder`,
  `new File(dir, name)`, `ObjectInputStream.readObject`, `DocumentBuilderFactory`,
  `RestTemplate`/`HttpClient` with dynamic URLs, unescaped JSP/Thymeleaf output.

### Building a probe: compile directly, do not use Maven

**For a probe, do not run Maven at all.** Compile the target classes and your probe runner
straight with the workspace JDK (OpenJDK 17), then run on the classpath:

```bash
javac -d /tmp/probe_classes $(find src/main/java -name '*.java') ProbeRunner.java
java -cp /tmp/probe_classes ProbeRunner
```

This is faster and its output stays small. `mvn test` floods the budget with build logs and
needs network/dependency resolution the offline probe sandbox does not have; a JUnit test is
unnecessary — a `main` method that calls the real target and prints the `HARNESS_PROBE` line
is enough (see `probe` and `cwe-611-xxe`). Use `--release 17` or no `--release` flag; never
`--release 7`, which omits APIs such as `XMLConstants.ACCESS_EXTERNAL_DTD`.

### Only when the target genuinely needs dependencies

Fall back to Maven only when the target will not compile or run without declared dependencies.
**Before the first Maven, Gradle or `java` command**, run this in the workspace and keep it
for every later command (the sandbox user has no home directory, so Java otherwise writes
into a directory literally named `?`):

  ```bash
  export JAVA_TOOL_OPTIONS="-Duser.home=/workspace/repo/.harness-home -Djava.net.preferIPv4Stack=true"
  mvn -q -Dmaven.repo.local=/workspace/repo/.m2 dependency:go-offline
  ```

  Then compile/run with that same `-Dmaven.repo.local=/workspace/repo/.m2` and `-q`, resolving
  once online with `dependency:go-offline` and building offline with `-o`. Prefer
  `mvn -o -q -Dmaven.repo.local=/workspace/repo/.m2 compile` plus a direct `java -cp` runner
  over `mvn test`. Dependencies resolve only in the workspace, never in the offline probe. If
  `go-offline` fails, read the first error and fix that cause (the `environment` skill covers
  the trust store); do not search the filesystem for jars, do not use `pip` or `curl`, and do
  not rerun the same failing command.

## Completion criteria

- You can name the build system, the source and test roots, and the package layout.

