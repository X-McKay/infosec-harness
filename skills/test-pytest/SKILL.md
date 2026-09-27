---
name: test-pytest
description: How to write a probe as a pytest test that emits the oracle markers. Use this when authoring
  or repairing a probe for a pytest repository.
metadata:
  owner: appsec
  version: 1.0.0
---

# Probes in pytest

<!-- generated: activation criteria (scripts/restructure_skills.py) -->

## Use this skill when

- You are writing or repairing a probe and the repository's test framework is pytest or unittest.

## Do not use this skill when

- The repository uses a different framework; load that `test-*` skill.
- You have not yet read `probe-oracle-protocol`; read it first.

<!-- /generated: activation criteria -->

- Place the file at the planned repo-relative path (e.g. `tests/test_harness_probe_<id>.py`),
  matching the repo's import setup so it can import the code under test.
- Read the nonce from the task input and inline it as a constant.
- Do **not** let an assertion outcome be the signal; print markers and let the test end.

```python
def test_probe():
    NONCE = "<nonce>"
    from mypkg.module import target_callable        # the real sink owner
    import sys
    payload = build_input(NONCE)                     # per the cwe-* skill
    print(f"HARNESS_PRECONDITION::{NONCE}", flush=True)   # reached the sink
    result = target_callable(payload)
    if exploit_condition_holds(result, NONCE):
        print(f"HARNESS_ORACLE::{NONCE}", flush=True)
```

- Run with `python -m pytest -q -s {test_file}` so stdout is not swallowed.
- For a canary-file oracle, do not print the oracle marker; let the payload create
  `/tmp/harness_canary_<nonce>` and assert nothing.

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
