---
name: lang-java
description: "Conventions for reading Java repos: Maven/Gradle layout, entry points, and JUnit tests."
---

# Java repositories

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
