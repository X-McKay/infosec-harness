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
    payload = build_input(NONCE)                     # per the cwe-* skill
    print(f"HARNESS_PRECONDITION::{NONCE}", flush=True)   # about to call the sink
    try:
        result = target_callable(payload)
    except TargetRejectedInput:                      # the code refused it: that is a negative
        print(f"HARNESS_SINK_RETURNED::{NONCE}", flush=True)
        return
    print(f"HARNESS_SINK_RETURNED::{NONCE}", flush=True)  # the sink ran and returned
    if exploit_condition_holds(result, NONCE):
        print(f"HARNESS_ORACLE::{NONCE}", flush=True)
```

- Run with `python -m pytest -q -s -o addopts= {test_file}`. Both flags are load-bearing.
  `-s` keeps stdout out of pytest's capture. `-o addopts=` discards the project's own
  `addopts`, which pytest prepends to *our* invocation from pytest.ini, setup.cfg, tox.ini or
  pyproject.toml. Verified against real pytest: `-s` does override an inherited
  `--capture=sys`, so capture is not the danger — but `addopts = --collect-only` makes pytest
  exit **0** having printed neither the markers nor the words "collected 0 items". The probe
  silently never runs, and nothing downstream can tell the difference from a probe that ran and
  saw nothing. `-x` and `-p no:...` in a project's addopts do the same.
- For a canary-file oracle, do not print the oracle marker; let the payload create
  `/tmp/harness_canary_<nonce>` and assert nothing.

## Never skip or disable the probe

**Do not use `pytest.importorskip`, `pytest.skip`, `@pytest.mark.skip`, `@pytest.mark.skipif`,
or `@pytest.mark.xfail`.** A skipped test prints no markers, and pytest reports `collected 0
items` or `1 skipped` — which the harness cannot tell from a probe that is broken. The
probe-oracle-protocol names `collected 0 items` as a zero-test run, and a zero-test run is
never a negative result: nothing exercised the sink, so it says nothing about exploitability.

`importorskip` is the natural pytest way to say "this dependency isn't installed", and that is
precisely the judgement a probe must not make. If a module the probe needs is absent, let the
import fail: an `ImportError` naming the missing module is an *environment* signal that build
repair can act on, and it now routes back to environment repair. `importorskip` converts that
signal into silence, and the finding comes back inconclusive.

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
