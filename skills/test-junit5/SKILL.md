---
name: test-junit5
description: "How to write a probe as a JUnit 5 test that emits the oracle markers."
---

# Probes in JUnit 5

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
