---
name: environment
description: Prepare and repair a focused investigation environment using observed repository manifests and tool results.
---

Read the manifests and relevant source before installing anything. Use `execute` in the
workspace to inspect available runtimes, dependencies, and test commands. The image and
network permissions are operator-selected; instructions cannot widen them.

Keep the original source unchanged. Put new probes and dependencies under `/workspace/repo`
so they can be copied into the fresh offline probe sandbox. Use a separate dependency folder
such as `.harness-deps` and an external cache when a tool would rewrite tracked files. Avoid
virtualenv symlinks: the transfer accepts regular files/directories only. Never rely on files
in `/tmp` or a home directory surviving into the probe sandbox.

Choose the smallest environment that exercises the actual target. These are starting points,
not mandatory command templates:

| Repository | Useful approach |
| --- | --- |
| Python | Read pyproject/requirements. Install only needed packages with `python -m pip install --target .harness-deps ...`, then use `PYTHONPATH=.harness-deps`. Standard-library probes often need no install. |
| Node | Read package.json and its lockfile. Prefer existing dependencies; use declared runner binaries directly. Installation scripts execute untrusted repository code and stay inside OpenShell. Avoid changing the original lockfile or package.json. |
| Java/Maven | Inspect pom.xml, compiler level, and test provider. Put Maven's dependency cache inside the copied workspace; use offline mode for probes. JUnit 5 needs a compatible Surefire provider. Select the actual test class, not a source filename. |
| Java/Gradle | Inspect wrapper/build settings and available JDK. Cache dependencies in the workspace. Force a real test execution when incremental tasks would otherwise be up-to-date; ensure test stdout is forwarded. |
| Perl | Inspect Makefile.PL/cpanfile and actual imports. Prefer core modules where sufficient. Keep required libraries under the copied workspace; use verbose TAP output when diagnosing discovery. |

Observe each failure. Diagnose missing dependency, wrong toolchain, compilation, discovery,
and target behavior separately. Never convert a failed install/build/test into success with
`|| true`, skipped tests, or an invented package. Policy denial and unavailable runtimes are
limitations to report, not invitations to fetch through another endpoint or elevate privileges.

Use `run_probe` for evidence-bearing execution: that sandbox has no network or provider
attachment. A successful setup command alone does not establish exploitability or safety.
