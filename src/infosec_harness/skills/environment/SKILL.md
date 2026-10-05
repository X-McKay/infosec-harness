---
name: environment
description: Prepare and repair a focused investigation environment using observed repository manifests and tool results.
---

Read the manifests and relevant source before installing anything. Use `execute` in the
workspace to inspect available runtimes, dependencies, and test commands. The image and
network permissions are operator-selected; instructions cannot widen them.

Keep the original source unchanged. Put new probes and dependencies under `/workspace/repo`
so they can be copied into the fresh offline probe sandbox. Use a separate dependency folder
such as `.harness-deps` and an external cache when a tool would rewrite tracked files.
Avoid dependency symlinks, including virtualenv links and npm bin links: the transfer accepts
regular files and directories only (see `probe` for what transfers).

Choose the smallest environment that exercises the actual target. These are starting points,
not mandatory command templates:

| Repository | Useful approach |
| --- | --- |
| Python | Read pyproject/requirements. Install only needed packages with `python -m pip install --target .harness-deps ...`, then use `PYTHONPATH=.harness-deps`. Standard-library probes often need no install. |
| Node | Read package.json and its lockfile. Prefer existing dependencies; use declared runner binaries directly and install with `--no-bin-links` when appropriate. Installation scripts execute untrusted repository code and stay inside OpenShell. Avoid changing the original lockfile or package.json. |
| Java/Maven | Inspect pom.xml, compiler level, and test provider. Put Maven's dependency cache inside the copied workspace; use offline mode for probes. JUnit 5 needs a compatible Surefire provider. Select the actual test class, not a source filename. |
| Java/Gradle | Inspect wrapper/build settings and available JDK. Cache dependencies in the workspace. Force a real test execution when incremental tasks would otherwise be up-to-date; ensure test stdout is forwarded. |
| Perl | Inspect Makefile.PL/cpanfile and actual imports. Prefer core modules where sufficient. Keep required libraries under the copied workspace; use verbose TAP output when diagnosing discovery. |

Native Java package downloads can need IPv4 sockets and the supervisor's public TLS CA.
If Java reports `Permission denied` or a PKIX trust failure, inspect the runtime and the
public certificate at `NODE_EXTRA_CA_CERTS`. Copy the observed JDK's
`lib/security/cacerts` as a regular file into `.harness-deps/native-java-cacerts`, then import
that public certificate with the JDK's `keytool -importcert -noprompt` and store password
`changeit`. Preserve the JDK's existing trusted roots; never disable certificate verification.
Apply these JVM options through process-scoped `JAVA_TOOL_OPTIONS` when running Maven or Java:

```text
-Djava.net.preferIPv4Stack=true
-Djavax.net.ssl.trustStore=/workspace/repo/.harness-deps/native-java-cacerts
-Djavax.net.ssl.trustStorePassword=changeit
```

Maven command-line `-D` properties alone do not set these JVM startup options. Keep its
local repository under `/workspace/repo/.m2`. Preserve the manifest's compiler level;
an older compiler plugin may need explicit source/target properties matching a declared
release. Diagnose individual dependency-transfer failures before retrying a completed failed
build; do not treat an unknown execution outcome as a retryable build failure.

Observe each failure. Diagnose missing dependency, wrong toolchain, compilation, discovery,
and target behavior separately. Never convert a failed install/build/test into success with
`|| true`, skipped tests, or an invented package. Policy denial and unavailable runtimes are
limitations to report, not invitations to fetch through another endpoint or elevate privileges.

Use `run_probe` for evidence-bearing execution: that sandbox has no network or provider
attachment. A successful setup command alone does not establish exploitability or safety.
