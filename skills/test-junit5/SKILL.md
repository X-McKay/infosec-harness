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

- Name the class distinctly (e.g. `HarnessProbeTest`) and place it under `src/test/java/...`;
  the build/test command targets this class name.
- Inline the nonce as a constant. Print markers to `System.out`; do not rely on assertions.

```java
import org.junit.jupiter.api.Test;

class HarnessProbeTest {
    static final String NONCE = "<nonce>";

    @Test
    void probe() throws Exception {
        var payload = buildInput(NONCE);                 // per the cwe-* skill
        System.out.println("HARNESS_PRECONDITION::" + NONCE);   // reached the sink
        var result = Target.vulnerableCallable(payload); // the real sink owner
        if (exploitConditionHolds(result, NONCE)) {
            System.out.println("HARNESS_ORACLE::" + NONCE);
        }
    }
}
```

- Maven: `mvn -q -B -o test -Dtest=HarnessProbeTest`. Gradle:
  `./gradlew --offline test --tests '*HarnessProbeTest'`.
- For a canary oracle, let the payload create `/tmp/harness_canary_<nonce>`; assert nothing.

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

<!-- /generated: constraints -->
