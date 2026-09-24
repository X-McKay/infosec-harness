---
name: test-pytest
description: "How to write a probe as a pytest test that emits the oracle markers."
---

# Probes in pytest

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
