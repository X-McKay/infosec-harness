---
name: probe
description: Author and run a focused offline vulnerability probe with explicit positive and negative controls.
---

Trace the finding's real attacker-controlled value to the sensitive operation. Load the
relevant language and CWE skills. Write a new probe without modifying any original source
file. Inspect the actual function signature and preconditions rather than inventing a
standalone reimplementation of the vulnerable function.

Use `write` to add probe files and `execute` for preparation. Call `run_probe` to execute
inside a fresh offline OpenShell sandbox. It copies the prepared workspace, checks original
source bytes against the immutable snapshot, and records actual process results. Changes to
original source invalidate the probe; do not patch the target to manufacture a conclusion.

The probe must exercise the real target and report evidence for both controls:

- A positive control demonstrates the observation/oracle can detect the claimed behavior.
- A negative control demonstrates the oracle does not fire on a known-safe/control input.
- The actual finding input must reach the target; an exception during setup is not evidence
  that the target rejects an attack.
- Report whether the vulnerability was observed. A false value is meaningful only when the
  target was reached and the oracle and both controls worked.

Print exactly one final line with this shape, filling booleans from actual observations:

```text
HARNESS_PROBE {"target_reached":true,"oracle_valid":true,"positive_control":true,"negative_control":true,"vulnerability_observed":false}
```

The prefix and JSON must be on the same final stdout line. Printing JSON and then a
standalone `HARNESS_PROBE` line is invalid. Include only these five boolean fields;
print details earlier. In Python, after deriving `observations` from the actual checks:

```python
print('HARNESS_PROBE '+json.dumps(observations))
```

Never print a successful control without executing it. Marker values are self-reported claims,
not independent proof. The runtime also requires an actual successful, complete offline
execution and source citations before accepting a definitive verdict.

Ensure the runner really discovers and runs the probe. Exit code zero with zero tests is not
success. Pytest may capture stdout; Jest/Vitest may silence console output; Gradle may skip an
up-to-date task; Maven may select the wrong JUnit provider. Inspect runner output and use the
appropriate flags for this repository. Do not guess a framework from descriptive text.

Cite the `run_probe` evidence ID and exact source lines in the final verdict. Distinguish a
concrete blocker from an unexecuted path, missing dependency, timeout, or inconclusive result.
Persistent source changes are checked after execution, but a hostile probe can mutate and
restore files; do not claim independent semantic attestation of untrusted test code.
