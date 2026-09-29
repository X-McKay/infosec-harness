---
name: test-junit5
description: How to write a probe as a JUnit 5 (Jupiter) test that emits the oracle markers. Use this
  when authoring or repairing a probe for a repository with junit-jupiter on its test classpath.
metadata:
  owner: appsec
  version: 1.0.0
---

# Probes in JUnit 5

<!-- generated: activation criteria (scripts/restructure_skills.py) -->

## Use this skill when

- You are writing or repairing a probe and the repository's test framework is JUnit 5 — `junit-jupiter` or `junit-platform` is on the test classpath.

## Do not use this skill when

- The repository's tests are JUnit 4 (`org.junit.Test`, `junit:junit`) and jupiter is absent — use `test-junit4`.
- The repository uses a different framework; load that `test-*` skill.
- You have not yet read `probe-oracle-protocol`; read it first.

## When another skill also applies

- `test-junit4` also fires on the repositories that have *both* `junit:junit` and `junit-jupiter` on the test classpath, and each skill's negative criteria send the reader to the other. **This skill wins** whenever jupiter is present at all: Surefire 3.2.5 then selects the JUnit Platform provider, which does not run a JUnit-4-annotated test — measured as `Tests run: 0` with exit 0, the one shape the harness cannot tell from a probe that reached nothing. Defer to `test-junit4` only when jupiter is absent from the test classpath.

<!-- /generated: activation criteria -->

JVM runners select a test by **class**, not by file path, so the probe's identity has to line
up in three places at once. Get these right before writing the body:

- **Class name:** `HarnessProbeTest`. The test command's selector (`-Dtest=HarnessProbeTest`,
  `--tests '*HarnessProbeTest'`) names exactly this, and a selector that matches nothing fails
  the build with "No tests were executed" — which looks downstream like a defective probe.
- **Package:** declare the same package as the code under test (`package com.example;`) so the
  probe can reach package-private members and needs no import gymnastics.
- **Path:** `src/test/java/<package as directories>/HarnessProbeTest.java`. A file whose path
  and `package` disagree does not compile. If the pom sets `<testSourceDirectory>`, write the
  probe *there* instead: a file outside the declared test root is never compiled, and the run
  fails with `No tests matching pattern "HarnessProbeTest" were executed!` (measured).
- **Dependencies:** the probe is compiled at probe time with the classpath the image already
  has. Use only JDK classes and what the pom/build file already declares (JUnit 5 is there, or
  the environment plan added it) — a new library cannot be fetched: the probe container has no
  network.
- **Confirm jupiter really is on the test classpath before writing a jupiter probe.** If the pom
  declares only `junit:junit`, `org.junit.jupiter.api.Test` does not compile at all — `package
  org.junit.jupiter.api does not exist` — and the probe belongs in the JUnit 4 shape instead; see
  `test-junit4`. This is the common case in older repositories, not an edge case.
- Inline the nonce as a constant. Print markers to `System.out`; do not rely on assertions.

```java
package com.example;

import org.junit.jupiter.api.Test;

class HarnessProbeTest {
    static final String NONCE = "<nonce>";

    @Test
    void probe() throws Exception {
        String payload = buildInput(NONCE);              // per the cwe-* skill
        System.out.println("HARNESS_PRECONDITION::" + NONCE);   // about to call the sink
        String result;
        try {
            result = Target.vulnerableCallable(payload); // the real sink owner
        } catch (IllegalArgumentException | SecurityException rejected) {
            // The target refused the input: the code decided, and that is a negative.
            System.out.println("HARNESS_SINK_RETURNED::" + NONCE);
            return;
        }
        System.out.println("HARNESS_SINK_RETURNED::" + NONCE);  // the call produced an outcome
        if (exploitConditionHolds(result, NONCE)) {
            System.out.println("HARNESS_ORACLE::" + NONCE);
        }
    }
}
```

- Maven: `mvn -B -o test-compile org.apache.maven.plugins:maven-surefire-plugin:3.2.5:test
  -Dtest=HarnessProbeTest -Dmaven.repo.local=/work/home/.m2/repository
  -Dmaven.test.redirectTestOutputToFile=false`. Gradle:
  `./gradlew --offline -i test --tests '*HarnessProbeTest'`. Both shapes are deliberate and the
  reasons are in build-maven and build-gradle: Maven's default Surefire cannot see a JUnit 5
  test at all, and both runners hide a test's stdout unless told not to.
- **Do not write `var`, and do not assume a JUnit 5 project is a modern-Java project.** The
  declaration above is spelled out for a reason: `var` needs Java 10, and a jupiter project pinned
  to `maven.compiler.source` 8 — which is ordinary — fails the whole build with
  `cannot find symbol: class var`. Measured. Read the declared level before using any syntax newer
  than it.
- **If the project's *own* tests are JUnit 4 but jupiter is also on the classpath, still write a
  jupiter probe.** Surefire 3.2.5 selects the JUnit Platform provider as soon as jupiter is
  present, and it runs a JUnit-4-annotated test only when `junit-vintage-engine` is there too;
  without vintage the run reports `Tests run: 0` and **exits 0**, so a correct JUnit 4 probe is
  recorded as having reached nothing. Both halves of that were measured.
- **If the Maven run fails on `surefire-junit-platform:jar:… (absent)`, the probe is not the
  problem — the build is.** Surefire resolves that provider at test-execution time, so the
  `-o` run can only find it if the build already warmed it by *running* a test. That is a
  build-repair fix, not a probe-repair one; build-maven has the warm-up command. Do not respond
  by rewriting the probe, and do not relax the offline flag: the probe container has no network.
- For a canary oracle, let the payload create `/tmp/harness_canary_<nonce>`; assert nothing.

## Never skip or disable the probe

**Do not use `@Disabled`, `@Ignore`, or `Assumptions.assumeTrue/assumeFalse/assumingThat`.** An
aborted or disabled test prints no markers, and Surefire reports it as *skipped* — which the
harness cannot tell from a probe that is broken. Probe repair is then asked to fix a probe that
was correct and burns its whole budget on it.

An assumption is the natural JUnit way to say "the environment isn't right for this test", and
that is precisely the judgement a probe must not make. If a class, method or resource the probe
needs is absent, let it fail: a compile error or an exception with the missing name in it is an
*environment* signal that build repair can act on. `assumeTrue` converts that signal into
silence.

Assertions are for the same reason not the oracle: a failing assertion is a crash, and a crash
is indistinguishable from a broken probe. Print the marker on the true branch and let the test
end normally either way.

<!-- generated: constraints (scripts/restructure_skills.py) -->

## Safety constraints

- The test must run to completion and print its markers whether or not the exploit condition holds. Never let an assertion failure be the signal.
- Confine every effect to the sandbox temp dir. The probe has no network.
- Do not mock, stub, or reimplement the sink: call the smallest real callable that owns it.

## Completion criteria

- The probe prints the precondition marker at the moment it reaches the sink call.
- It emits the oracle signal only when the exploit condition actually holds.
- It runs to completion and exits cleanly either way.
- Framework output is not captured away, so the markers reach the runner's stdout.
- The probe cannot decline to run: no skip, no disable, no assumption guard. A skipped test prints no markers, which the harness cannot distinguish from a broken probe, so probe repair is handed a correct probe and exhausts its budget on it.
- The probe compiles at the level the project declares: `var` needs Java 10 or newer, and a JUnit 5 project can still be pinned to `maven.compiler.source` 8.

<!-- /generated: constraints -->
