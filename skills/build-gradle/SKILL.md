---
name: build-gradle
description: "Recipe for building a Gradle Java test environment in the sandbox."
---

# Building Gradle targets

- **Base image:** `gradle:8-jdk21` or an Eclipse Temurin image plus the repo's `./gradlew`.
- **Install / compile:** prefer the wrapper: `./gradlew --no-daemon testClasses` to resolve
  dependencies and compile test sources. Use `--offline` on the probe run.
- **test_command:** `./gradlew --no-daemon --offline test --tests '<fqcn>'` targeting the
  probe's fully-qualified class.
- **Registries:** honor `settings.gradle`/`init.gradle` repositories the project declares;
  supply credentials via BuildKit secrets.
- **Partial builds:** target a subproject: `./gradlew :<subproject>:test --tests '<fqcn>'`.
