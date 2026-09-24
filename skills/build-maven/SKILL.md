---
name: build-maven
description: "Recipe for building a Maven Java test environment in the sandbox."
---

# Building Maven targets

- **Base image:** `maven:3.9-eclipse-temurin-21` (drop to `-17` if the project targets 17).
- **Install / compile:** `mvn -q -B -DskipTests test-compile` to pull dependencies and compile
  main + test sources. Use `-s <settings.xml>` when the repo ships one (private registries,
  mirrors); pass registry credentials as BuildKit secrets, never in the image.
- **test_command:** run one test class: `mvn -q -B -o test -Dtest=<ProbeClassName>`
  (`-o` offline so the probe run needs no network; everything is already resolved at build).
  Match `<ProbeClassName>` to the probe's class (see test-junit5).
- **Partial builds:** `mvn -q -B -pl <module> -am -DskipTests test-compile`, then
  `-pl <module>` on the test command (see partial-build).
