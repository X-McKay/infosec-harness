---
name: investigate
description: Trace and test an identified vulnerability with source evidence and bounded offline experiments.
---

Establish what the finding actually claims and the assumptions it needs. Read the affected
implementation and its callers. Follow the trust boundary from attacker-controlled input to
the sensitive operation, including validation, encoding, permissions, deployment configuration,
and framework behavior. Inspect tests and dependency versions when they affect that path.

Choose experiments that discriminate between competing explanations. State the input,
precondition, expected observation and counterexample before interpreting results. Run a positive
control when a negative result could instead mean that the fixture never reached the target.
Load the relevant language, environment, probe and CWE skills as needed. Install or build prerequisites
in the workspace, then use `run_probe` for offline execution. A failed build, unreachable target,
crash or timeout may establish a limitation without establishing exploitability.

Keep the original finding's scope. Cite source paths and original line numbers. Record exact
execution evidence ids returned by tools. Changes written for experiments are sandbox fixtures;
they do not establish behavior of the original source without a supported connection. Explain
what an attacker controls, what they gain, and which concrete boundary succeeds or blocks them.
Use inconclusive when prerequisites or evidence remain unresolved.
