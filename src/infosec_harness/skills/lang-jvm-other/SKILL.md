---
name: lang-jvm-other
description: Kotlin, Scala, Groovy and Gradle-built JVM repositories. Use this when a JVM repository is not plain Java on Maven.
metadata:
  owner: appsec
  version: 1.0.0
---

# Kotlin, Scala, Groovy and Gradle projects

## First: check the toolchain

The image has OpenJDK 17 and Maven only. `gradle`, `kotlinc`, `scalac`, `sbt` and `groovy`
are **not** installed. Run `command -v java mvn gradle kotlinc scalac sbt groovy` before
planning, and read `lang-java` for the Maven and `JAVA_TOOL_OPTIONS` conventions.

## Use this skill when

- The repository has `build.gradle(.kts)`, `settings.gradle(.kts)`, `build.sbt`, or sources
  under `src/main/kotlin`, `src/main/scala` or `src/main/groovy`, or a `Jenkinsfile`.

## Do not use this skill when

- The repository is plain Java built with Maven — use `lang-java`.
- Clojure (`project.clj`, `deps.edn`) — use `triage-unknown-language`.
- You are planning installs — use `environment`. This skill grants no permissions.

## Recognize the project

- **Gradle:** `gradlew` plus `gradle/wrapper/gradle-wrapper.properties` (`distributionUrl`),
  `libs.versions.toml` catalogs, `buildSrc/`. **sbt:** `build.sbt`, `project/build.properties`.
  **Maven with plugins:** `kotlin-maven-plugin`, `scala-maven-plugin`, `gmavenplus-plugin`.
- **Entry points:** Spring controllers (Kotlin), Ktor `routing { get(...) }`, Play/Akka HTTP
  routes (Scala), Grails controllers and Jenkins pipeline steps (Groovy), `main` functions.
- **Sinks to note:** the Java sinks in `lang-java`, plus Kotlin `"... $x"` templates into SQL;
  Scala `sys.process` (`"cmd $x".!` splits on spaces with no shell; `Seq("sh","-c",x)` uses
  one); Groovy `"cmd".execute()` (no shell), `Eval.me`/`GroovyShell.evaluate` (code), and
  `groovy.sql.Sql` with a GString, which **binds** `${x}` as a parameter (a frequent false
  positive) unless the query is built as a plain `String` first.

## What can build here

- **Maven projects using the Kotlin, Scala or Groovy plugins** build with the `lang-java`
  route: resolve once in the workspace (`dependency:go-offline`), compile offline, and write
  the classpath to a file with
  `mvn -o -q -Dmaven.repo.local=/workspace/repo/.m2 dependency:build-classpath -Dmdep.outputFile=.harness-build/cp.txt`.
- **Gradle projects** need a Gradle distribution. `./gradlew` downloads one from
  `distributionUrl`: that is an `environment` decision under the operator's policy, tried at
  most once in the workspace with `GRADLE_USER_HOME=/workspace/repo/.harness-home/gradle`. If
  the policy denies the download, stop: that is a limitation, not something to route around.
- **sbt and standalone compilers** are absent; there is no route to them here.

## Compile and run a probe

Write the probe in Java and launch it as a single source file, so no Kotlin or Scala compiler
is needed for the probe itself (classes and the language runtime jar come from the build):

```bash
java -cp "target/classes:$(cat .harness-build/cp.txt)" .harness-probe/HarnessProbe.java
```

Calling compiled code from Java: Kotlin top-level functions live in `FileNameKt`; companion
members are `Foo.Companion.bar()` unless `@JvmStatic`; default arguments need every parameter
unless `@JvmOverloads`; `internal` names are mangled (`name$module`). A Scala `object Foo` is
`Foo$.MODULE$`; Scala and Groovy classes are ordinary JVM classes. Reflection on the real class
is acceptable; a reimplementation is not.

Gradle prints `BUILD SUCCESSFUL` after test output, may skip up-to-date tasks and hides test
stdout by default: launch the probe with `java` directly for the evidence-bearing run.

## The HARNESS_PROBE line

Java `boolean` concatenates as `true`/`false`:

```java
System.out.println("HARNESS_PROBE {\"target_reached\":" + t + ",\"oracle_valid\":" + o
    + ",\"positive_control\":" + p + ",\"negative_control\":" + n
    + ",\"vulnerability_observed\":" + v + "}");
```

In Kotlin the same is `println("HARNESS_PROBE {\"target_reached\":$t,...}")` with `Boolean`
values; never print a Groovy truthy object or an `Int`.

## Common failure modes

- Missing Kotlin/Scala standard library on the classpath: it must come from the resolved build.
- Compiled classes absent because the build never ran: `target/classes` must come from this
  run, not from a committed jar of unknown provenance.
- A JDK newer than 17 required by `jvmTarget`/`release`: a limitation.

## When the toolchain is absent

Verify with `command -v` as above. If the project needs Gradle, sbt or a standalone compiler and
none is present (or the one Gradle wrapper download is denied), do not fetch distributions
another way and do not translate the code into Java (a translation is a stand-in). Return
`inconclusive`, name the exact missing tool (for example `gradle: not found; wrapper download
denied`) as the limitation in the verdict summary, and record what reading established. A
wrapper properties file naming a version is not execution evidence.

## Completion criteria

- You can name the build tool, how the classes and runtime jar reached the classpath, the
  JVM-visible name of the target, and either the probe you ran or the exact missing tool.
