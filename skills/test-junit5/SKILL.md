---
name: test-junit5
description: How to write a probe as a JUnit 5 test that emits the oracle markers. Use this when authoring
  or repairing a probe for a JUnit repository.
metadata:
  owner: appsec
  version: 1.0.0
---

# Probes in JUnit 5

<!-- generated: activation criteria (scripts/restructure_skills.py) -->

## Use this skill when

- You are writing or repairing a probe and the repository's test framework is JUnit 5.

## Do not use this skill when

- The repository uses a different framework; load that `test-*` skill.
- You have not yet read `probe-oracle-protocol`; read it first.

<!-- /generated: activation criteria -->

JVM runners select a test by **class**, not by file path, so the probe's identity has to line
up in three places at once. Get these right before writing the body:

- **Class name:** `HarnessProbeTest`. The test command's selector (`-Dtest=HarnessProbeTest`,
  `--tests '*HarnessProbeTest'`) names exactly this, and a selector that matches nothing fails
  the build with "No tests were executed" — which looks downstream like a defective probe.
- **Package:** declare the same package as the code under test (`package com.example;`) so the
  probe can reach package-private members and needs no import gymnastics.
- **Path:** `src/test/java/<package as directories>/HarnessProbeTest.java`. A file whose path
  and `package` disagree does not compile.
- **Dependencies:** the probe is compiled at probe time with the classpath the image already
  has. Use only JDK classes and what the pom/build file already declares (JUnit 5 is there, or
  the environment plan added it) — a new library cannot be fetched: the probe container has no
  network.
- Inline the nonce as a constant. Print markers to `System.out`; do not rely on assertions.

```java
package com.example;

import org.junit.jupiter.api.Test;

class HarnessProbeTest {
    static final String NONCE = "<nonce>";

    @Test
    void probe() throws Exception {
        var payload = buildInput(NONCE);                 // per the cwe-* skill
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
  -Dtest=HarnessProbeTest -Dmaven.test.redirectTestOutputToFile=false`. Gradle:
  `./gradlew --offline -i test --tests '*HarnessProbeTest'`. Both shapes are deliberate and the
  reasons are in build-maven and build-gradle: Maven's default Surefire cannot see a JUnit 5
  test at all, and both runners hide a test's stdout unless told not to.
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

<!-- /generated: constraints -->
