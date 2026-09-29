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

## When another skill also applies

- `build-gradle` also fires on the repositories that carry both a `pom.xml` and a `build.gradle` — a Gradle build kept beside a published pom, or a migration half done — and each skill's negative criteria send the reader to the other, so on their own the two deadlock. **This skill wins** when the module holding the finding's sink is the one Maven builds, meaning its sources sit under a directory some `pom.xml` declares; otherwise defer to `build-gradle`. The tie has to be broken because the two recipes differ in the flag that lets a probe's markers out (`-Dmaven.test.redirectTestOutputToFile=false` here, Gradle's `-i` there), so a spec assembled from the wrong recipe runs a correct probe and records nothing.

<!-- /generated: activation criteria -->

- **Read the project's test framework first. It changes the install commands, not just the probe.**
  Guess wrong and the *warm-up* fails to compile, so no image is built at all. Every row executed
  under Maven 3.9.16 / Surefire 3.2.5:

  | the pom's test classpath has | framework | Surefire auto-selects |
  | --- | --- | --- |
  | `junit-jupiter`/`junit-platform` (even beside `junit:junit`) | junit5 | `surefire-junit-platform` |
  | `junit:junit` 4.x, or JUnit 3-style `junit.framework.TestCase` | junit4 | `surefire-junit4` |
  | `org.testng:testng`, with or without `junit:junit` | testng | `surefire-testng` |
  | nothing declared at all | none | — no probe can compile; report the environment unbuildable |

  **Do not assume JUnit 5.** Of the 51 Maven entries harvested from Vul4J, 50 are JUnit 4 and one
  is JUnit 5.
- **Set the local repository explicitly, to two different paths.** Verified against the corpus:
  `-Dmaven.repo.local=/opt/home/.m2/repository` on every install command,
  `-Dmaven.repo.local=/work/home/.m2/repository` on the test command. Maven takes its local
  repository from the JVM's `user.home`, and the sandbox user has no passwd entry, so that resolves
  to `/root` and the build dies with `cannot create directory '/root': Permission denied` before
  resolving anything. The paths differ because the image is built with `HOME=/opt/home` and the
  probe runs from a `/work/home` copy of it.
- **Warm Surefire by *running* a test, written in the project's own framework.** This is the
  difference between a Java target that scores and one that scores nothing. Surefire resolves its
  **provider** lazily, at test-execution time, from what is on the test classpath — so a warm-up
  that invokes the pinned goal with nothing to run (`-DfailIfNoTests=false`, empty test tree)
  fetches the plugin and all of its own dependencies, reports BUILD SUCCESS, and stops short of the
  provider. The offline probe then dies with `surefire-junit4:jar:3.2.5 (absent) … has not been
  downloaded from it before` — exit 0 from the build and nothing from the probe, the shape neither
  build repair (it sees no failure) nor probe repair (the probe is correct) can act on. Which
  artifact is absent is per-project: `surefire-junit-platform` for JUnit 5, `surefire-testng` for
  TestNG. A warm-up in the **wrong** framework fails earlier still, in its own `test-compile`:
  `HarnessWarmupTest.java:[1,63] cannot find symbol / symbol: class Test`. Measured on three
  harvested repositories at their vulnerable revisions (zeroturnaround/zt-zip,
  apache/commons-imaging, apache/commons-fileupload) and on fixtures at source 1.5–1.8 under JDK
  8/11/17/21; with the matching warm-up those three run an offline probe printing all three markers.
- **Do not pin the provider instead.** `dependency:get` on the provider only moves the failure to
  the next artifact, `junit-platform-launcher`, whose version Surefire derives from the project's
  own JUnit and which no fixed list can predict (one run fetched 1.9.3 and 1.10.2).
  `resolve-plugins` is worse: it resolves the effective pom, i.e. Surefire 2.12.4. And **dropping
  `-o` is not a fallback** — probe containers have no network.
- **Base image: read the declared language level, then pick the JDK.** Take the **oldest** level
  anything declares (`maven.compiler.release`, `source`/`target`, `<java.version>`; multi-module
  projects usually declare them in the root pom) — a module at source 7 binds the whole build.

  | project declares | use | because |
  | --- | --- | --- |
  | Java 5 | `maven:3.9-eclipse-temurin-8` | JDK 11 already refuses `-source 5` |
  | Java 6 | `maven:3.9-eclipse-temurin-11` | JDK 17 refuses 6 |
  | Java 7 | `maven:3.9-eclipse-temurin-17` | JDK 21 refuses 7 |
  | Java 8–17, or nothing | `maven:3.9-eclipse-temurin-17` | the compiler plugin's default level is 8 |
  | Java 21 | `maven:3.9-eclipse-temurin-21` | |

  Those floors were **executed**, not read off a release note: javac from Zulu 8/11/17/21 under
  Maven 3.9.16, asked for `-source 1.5/1.6/1.7/1.8`. JDK 8 took all four; JDK 11 refused 5
  ("Source option 5 is no longer supported. Use 6 or later."); JDK 17 refused 6; JDK 21 refused 7.
  The corpus needs every row: 14 of 58 entries are Java 7, one pom pins source 1.6, three pin 1.5.
  Both directions are hard failures with fixed javac messages. **Never fix it by raising the
  project's compiler level**: that edits the code under test and changes what the probe measures.
- **Never `-q`; use `-B`.** Maven relays the forked test JVM's stdout through its own logger at
  INFO, so `-q` raises the threshold above the `HARNESS_` markers and a passing probe is recorded as
  having reached nothing. The Maven form of pytest without `-s`.
- **Install / compile — two commands:**

  ```
  mvn -B -Dmaven.repo.local=/opt/home/.m2/repository -DskipTests test-compile
  mkdir -p src/test/java && echo 'import org.junit.Test; public class HarnessWarmupTest { @Test public void warm() {} }' > src/test/java/HarnessWarmupTest.java && mvn -B -Dmaven.repo.local=/opt/home/.m2/repository test-compile org.apache.maven.plugins:maven-surefire-plugin:3.2.5:test -Dtest=HarnessWarmupTest && rm -f src/test/java/HarnessWarmupTest.java target/test-classes/HarnessWarmupTest.class
  ```

  The second line is the warm-up above in its **junit4** form; for **junit5** substitute
  `import org.junit.jupiter.api.Test; class HarnessWarmupTest { @Test void warm() {} }`, for
  **testng** `import org.testng.annotations.Test; public class HarnessWarmupTest { @Test public void
  warm() {} }`. One line with `echo` and no heredoc, because each install command becomes a single
  Dockerfile `RUN`. `public class`/`public void` in the junit4 and testng forms, because JUnit 4
  does not run a package-private method: the JUnit4Provider reports `initializationError`, nothing
  runs, and nothing is fetched. No `-DfailIfNoTests=false` — that flag is what let the old warm-up
  pass while running nothing. Write it under the pom's `<testSourceDirectory>` if it sets one, or
  nothing written is compiled and the warm-up fails `No tests matching pattern "HarnessWarmupTest"
  were executed!` (measured). Use `-s <settings.xml>` when the repo ships one; registry credentials
  go in BuildKit secrets.
- **test_command — pin Surefire, and compile the probe:**

  ```
  mvn -B -o test-compile \
      org.apache.maven.plugins:maven-surefire-plugin:3.2.5:test \
      -Dtest=<ProbeClassName> -Dmaven.repo.local=/work/home/.m2/repository \
      -Dmaven.test.redirectTestOutputToFile=false
  ```

  - **`-Dmaven.repo.local=/work/home/.m2/repository`** — the probe-time path, *not* the build-time
    one. Omitting it is the easiest way to turn a correct command into a rejected one.
  - **`test-compile`, not `test`.** The probe is written into the container *after* the image is
    built, so the command must compile it — but the `test` phase (and `verify`, `package`,
    `install`) also triggers the pom's own Surefire execution.
  - **The fully-qualified, version-pinned goal.** Maven 3.x binds `maven-surefire-plugin:2.12.4` to
    the `test` phase, and 2.12.4 has **no JUnit Platform provider**: a JUnit 5 probe is never
    discovered and the build fails "No tests were executed". A phase-bound version cannot be
    overridden from the command line and you may not edit the pom, so naming the goal with its
    version is the only fix available. 3.2.5 covers JUnit 4 too (provider `surefire-junit4`,
    verified); use it unless the pom pins something newer.
  - **`-Dmaven.test.redirectTestOutputToFile=false`** keeps the markers on stdout, and **`-o`**
    keeps the run offline — which works only because the install step warmed the plugin *and* the
    provider by running a test.

  Match `<ProbeClassName>` to the probe's class (see test-junit4 / test-junit5).
- **The pom's own Surefire configuration outranks your `-D` flags.** The CLI coordinate fixes the
  *version* — a pom pinning 2.18.1 still runs 3.2.5's providers — but its plugin-level
  `<configuration>` still applies to the CLI invocation, and a parameter set there beats the `-D`
  that is merely its default. Measured in `<build><plugins>` and in `<pluginManagement>`:
  `<excludes>` naming the probe is harmless (`-Dtest=` wins);
  `<redirectTestOutputToFile>true</redirectTestOutputToFile>` cannot be turned off, so the probe
  passes, exits 0, and every marker goes to `target/surefire-reports/<class>-output.txt` — which
  `run_probe` reads back onto stdout for exactly this reason, so keep the flag and do nothing
  further; `<skipTests>true</skipTests>` is fatal — `Tests are skipped.`, no reports, **exit 0**,
  `-DskipTests=false` ignored, and no EnvironmentSpec can probe that project, so report it
  unbuildable. Both settings are harmless inside an `<executions><execution>` block (they do not
  reach a direct CLI goal) and overridable as pom *properties*.
- **A 2017-era pom offline: what breaks first.** Not the pom's age — Maven 3.9.16 compiled and
  tested the corpus's own root poms unchanged, `maven-compiler-plugin` 2.3.2 and 3.0 included. It is
  **Maven 3.8+'s HTTP blocker**: an artifact resolvable only from a `http://` repository the pom
  declares fails with `Could not transfer artifact … from/to maven-default-http-blocker
  (http://0.0.0.0/)`. It is almost always on Central over https, so pass a settings file mirroring
  the blocked repository id (`-s settings.xml`, `<mirrorOf>legacy</mirrorOf>`, Central's https
  `<url>`) — measured to lift the block. Do not edit the repository's pom.
- **Partial builds:** `mvn -B -Dmaven.repo.local=/opt/home/.m2/repository -pl <module> -am
  -DskipTests test-compile`, then `-pl <module>` on the test command (see partial-build).

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
- The base image's JDK still accepts the language level the project declares. Measured with Zulu 8/11/17/21: JDK 11 refuses `-source 5`, JDK 17 refuses 6, JDK 21 refuses 7 — so Java 5 needs temurin-8, Java 6 temurin-11, Java 7 temurin-17.
- An install command warms Surefire's provider by *running* a test written in the repository's own framework — a throwaway class run under the pinned goal with `-Dtest=` and then deleted — and not merely by invoking the plugin with `-DfailIfNoTests=false`. Surefire resolves the provider at test-execution time, so a warm-up that runs no test fetches the plugin and none of the provider and the offline probe fails on `surefire-junit4:jar:… (absent)`; and a warm-up written in the *wrong* framework does not compile at all, so the image is never built.

<!-- /generated: constraints -->
