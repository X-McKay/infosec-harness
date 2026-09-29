---
name: test-junit4
description: How to write a probe as a JUnit 4 (or JUnit 3) test that emits the oracle markers. Use
  this when authoring or repairing a probe for a repository whose tests use org.junit.Test or junit.framework.TestCase.
metadata:
  owner: appsec
  version: 1.0.0
---

# Probes in JUnit 4

<!-- generated: activation criteria (scripts/restructure_skills.py) -->

## Use this skill when

- You are writing or repairing a probe and the repository's test framework is JUnit 4 — its tests import `org.junit.Test`, or extend `junit.framework.TestCase`, and its build declares `junit:junit`.
- The repository declares no JUnit at all and you must choose: JUnit 4 is what the overwhelming majority of Java in the wild has on its test classpath.

## Do not use this skill when

- `junit-jupiter` is on the test classpath — use `test-junit5`.
- The repository uses a different framework; load that `test-*` skill.
- You have not yet read `probe-oracle-protocol`; read it first.

## When another skill also applies

- `test-junit5` also fires on the repositories that have *both* `junit:junit` and `junit-jupiter` on the test classpath — a migration part-done, which is common — and each skill's negative criteria send the reader to the other. **That skill wins** whenever jupiter is present at all, and the reason is measured: with `junit-jupiter` on the classpath Surefire 3.2.5 selects the JUnit Platform provider, and a JUnit-4-annotated probe then reports `Tests run: 0` and still exits 0 — a correct probe recorded as having reached nothing. It runs again only if `junit-vintage-engine` is also present, so use this skill when jupiter is absent (or vintage is present and the code under test is JUnit 4).

<!-- /generated: activation criteria -->

JVM runners select a test by **class**, not by file path, so the probe's identity has to line
up in three places at once. Get these right before writing the body:

- **Class name:** `HarnessProbeTest`, and the class must be `public`. The test command's
  selector (`-Dtest=HarnessProbeTest`) names exactly this.
- **Method:** `public void`, annotated `@Test` from `org.junit.Test`. **This is the JUnit 4 trap.**
  The JUnit 5 shape — `class HarnessProbeTest { @Test void probe() }` — compiles here and then
  fails at run time: JUnit 4 treats a package-private method as not runnable, so the
  JUnit4Provider reports `com.example.HarnessProbeTest.initializationError ... ERROR`, prints no
  markers, and exits nonzero. Measured under Surefire 3.2.5; it is indistinguishable downstream
  from a probe that is genuinely broken, and probe repair spends its whole budget on it.
- **Package:** declare the same package as the code under test (`package com.example;`) so the
  probe can reach package-private members and needs no import gymnastics.
- **Path:** `src/test/java/<package as directories>/HarnessProbeTest.java` — unless the pom sets
  `<testSourceDirectory>`, in which case write it there instead; a file outside the declared test
  root is never compiled, and the run then fails with
  `No tests matching pattern "HarnessProbeTest" were executed!` (measured).
- **Dependencies:** the probe is compiled at probe time with the classpath the image already
  has. Use only JDK classes and what the pom already declares — a new library cannot be fetched:
  the probe container has no network.
- Inline the nonce as a constant. Print markers to `System.out`; do not rely on assertions.

```java
package com.example;

import org.junit.Test;

public class HarnessProbeTest {
    static final String NONCE = "<nonce>";

    @Test
    public void probe() throws Exception {
        String payload = buildInput(NONCE);                  // per the cwe-* skill
        System.out.println("HARNESS_PRECONDITION::" + NONCE);   // about to call the sink
        String result;
        try {
            result = Target.vulnerableCallable(payload);  // the real sink owner
        } catch (IllegalArgumentException rejected) {
            // The target refused the input: the code decided, and that is a negative.
            System.out.println("HARNESS_SINK_RETURNED::" + NONCE);
            return;
        } catch (SecurityException rejected) {
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

- **Write it at the language level the project declares, not the one you are used to.** JUnit 4
  projects are old projects: read `maven.compiler.source` (or `<source>`) first. `var` needs
  Java 10 — at source 8 javac fails with `cannot find symbol: class var` — and the multi-catch
  `catch (A | B e)` needs Java 7, so at source 6 or 5 it has to be split into the two separate
  catch clauses above. Both were measured; both fail the whole build, not just the probe.
- Maven: `mvn -B -o test-compile org.apache.maven.plugins:maven-surefire-plugin:3.2.5:test
  -Dtest=HarnessProbeTest -Dmaven.repo.local=/work/home/.m2/repository
  -Dmaven.test.redirectTestOutputToFile=false`. Verified end to end on a `--network=none`-shaped
  offline run and on three real 2017-era repositories: Surefire 3.2.5 auto-selects
  `org.apache.maven.surefire.junit4.JUnit4Provider`, `-Dtest=HarnessProbeTest` matches the class
  by its simple name even when it is in a package, and all three markers reach stdout.
- **The pinned 3.2.5 is right for JUnit 4 as well as JUnit 5** — the provider it resolves is
  `surefire-junit4`, not `surefire-junit-platform`. That matters for the build: the warm-up has to
  run a **JUnit 4** test, because it is the project's classpath that decides which provider gets
  downloaded, and an un-warmed offline run fails with
  `org.apache.maven.surefire:surefire-junit4:jar:3.2.5 (absent)`. That is build-maven's job, not
  the probe's — do not respond to it by rewriting the probe.
- **If the project's tests extend `junit.framework.TestCase` (JUnit 3 style)**, that still runs
  under the JUnit4Provider on the `junit:junit` artifact. Either shape works; the TestCase shape
  needs the method named `testProbe` and no annotation:

  ```java
  public class HarnessProbeTest extends junit.framework.TestCase {
      public void testProbe() throws Exception { /* markers as above */ }
  }
  ```

- For a canary oracle, let the payload create `/tmp/harness_canary_<nonce>`; assert nothing.

## Never skip or disable the probe

**Do not use `@Ignore`, `org.junit.Assume.assumeTrue/assumeFalse/assumeNotNull`, or
`Assumptions`.** An ignored or aborted test prints no markers, and Surefire reports it as
*skipped* — which the harness cannot tell from a probe that is broken. Probe repair is then asked
to fix a probe that was correct and burns its whole budget on it.

An assumption is the natural JUnit way to say "the environment isn't right for this test", and
that is precisely the judgement a probe must not make. If a class, method or resource the probe
needs is absent, let it fail: a compile error or an exception with the missing name in it is an
*environment* signal that build repair can act on. `assumeTrue` converts that signal into
silence.

Assertions are for the same reason not the oracle: a failing assertion is a crash, and a crash
is indistinguishable from a broken probe. Print the marker on the true branch and let the test
end normally either way. `@Test(expected = ...)` is the same mistake in JUnit 4 clothing — it
makes the *absence* of an exception a failure, so the probe's outcome is carried by a pass/fail
rather than by a marker.

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
- The probe's class and its `@Test` method are both `public`. JUnit 4 does not run a package-private method: the JUnit4Provider reports `initializationError` ("No runnable methods"), prints no markers, and exits nonzero, which reads downstream as a defective probe.
- The probe compiles at the level the project declares: no `var` below Java 10, no multi-catch below Java 7. A JUnit 4 project is usually old enough for this to bite.

<!-- /generated: constraints -->
