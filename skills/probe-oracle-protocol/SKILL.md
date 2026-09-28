---
name: probe-oracle-protocol
description: The deterministic marker protocol every probe uses to report exploitability. Use this
  before planning or writing any probe, whatever the weakness class or test framework.
metadata:
  owner: appsec
  version: 1.0.0
---

# Probe oracle protocol

<!-- generated: activation criteria (scripts/restructure_skills.py) -->

## Use this skill when

- You are about to plan, write, or repair a probe.
- You need to decide what an oracle for this finding would observe.
- You are judging whether a probe execution means anything.

## Do not use this skill when

- You are profiling a repository or planning a build environment; no markers are involved yet.

<!-- /generated: activation criteria -->

A probe is a unit test whose job is to answer one question about a pre-identified finding:
**was the exploit condition observed when we drove untrusted input to the sink, in a
sandbox?** The answer must come from an explicit, observable signal, never from whether the
test "passed". This makes triage deterministic and lets the harness distinguish
*not exploitable* from *never reached the code*.

## The three markers

The runner passes a random `oracle_nonce` in the task input. Use it verbatim; it prevents a
repository's own output from being mistaken for a signal.

1. **Precondition marker** — print this once, on stdout, at the moment the test has reached
   the sink call (the input is about to be handed to the dangerous operation):

   ```
   HARNESS_PRECONDITION::<nonce>
   ```

   It tells the harness the test actually exercised the code path. A probe that never prints
   it is treated as *did not reach the sink* (a probe defect), not as a clean negative.

2. **Sink-returned marker** — print this once, on stdout, immediately after the call to the
   sink *returns*:

   ```
   HARNESS_SINK_RETURNED::<nonce>
   ```

   The precondition marker is printed *before* the call, so by itself it proves only that the
   probe meant to make it. Without this second marker a probe that threw on the way into the
   sink — a wrong import, a bad signature, an exception swallowed by a promise or a `try` —
   looks exactly like a probe whose payload the code resisted, and the harness records a false
   negative on an exploitable finding.

   **Print it once the sink has run and produced an outcome**, which includes the target
   *rejecting* the input: a containment check that raises, a validator that throws, a guard that
   returns an error are all the code under test deciding, and that is a negative. Catch that
   rejection, print the marker, and do not fire the oracle.

   **Do not print it when the call could not be made at all** — the symbol was not found, the
   signature was wrong, the import failed. That is a probe defect, and its absence is how the
   harness tells the two apart. A fired oracle implies the marker.

3. **Oracle signal** — emit this only when the exploit condition actually holds. Two forms:

   - `marker_output`: print, on stdout, exactly

     ```
     HARNESS_ORACLE::<nonce>
     ```

   - `canary_file`: when the only reliable evidence is a side effect (e.g. an injected OS
     command running), have the payload create the file `/tmp/harness_canary_<nonce>`. The
     runner detects it and treats it as the oracle firing. Never print the oracle marker
     yourself in this mode.

The harness scans captured output for these exact strings. Do not log them speculatively, in
comments, or inside the payload text — emit each only at its real moment.

## Rules

- **Run to completion.** The test must finish and print its markers regardless of assertion
  results. Do not `assert` the exploit and let a failure be the signal — a crash would look
  like a probe defect. Wrap the check and print the marker on the true branch.
- **Reach the real sink.** Call the smallest real callable that owns the sink. Do not mock the
  sink, and do not reimplement the code under test.
- **Confine effects to the sandbox.** The probe runs with no network. Any file effect must
  stay under the sandbox temp dir (`/tmp`). Never target real hosts, credentials, or paths
  outside the sandbox.
- **A run that executed zero tests is never a negative result.** If the runner reports it
  ran nothing — `prove`'s `skipped: (no reason given)` (a bare `1..0` plan), pytest's
  `collected 0 items`, Surefire's `Tests run: 0`, Jest's `No tests found` — then nothing
  exercised the sink, so the run says nothing about exploitability. Classify it
  `probe_defect`, never `valid_negative`. The harness detects these phrases deterministically
  and puts the reason on `probe_execution.runner_reported_no_tests`; when that field is set,
  believe it over any inference you would draw from the exit code. It is set precisely because
  the alternative was measured to fail: on `perl-cmdi-vulnerable` the runner printed
  `skipped: (no reason given)` with exit 255 and an **empty stderr**, the diagnosis guessed
  "the file was not written correctly", the repair loop fixed the wrong thing, and a genuinely
  exploitable finding came back `inconclusive`. A zero-test run has a short list of real
  causes — the file is not where the runner looks, the selector matches no test, the plan was
  emitted before the assertions, or the module failed to load — so say which and repair that.

- **Judge the observable effect, not the payload.** The oracle condition is about what the
  code *did* with the input (query not parameterized, value returned unescaped, command
  executed), not merely that you sent a suspicious-looking string.

## Minimal shape (language-neutral pseudocode)

```
nonce = <from task input>
setup the target object/module
print("HARNESS_PRECONDITION::" + nonce)      # about to call the sink
try:                                         # exercise the real sink
    result = target_callable(build_input(nonce))
except TargetRejectedInput:                  # the code refused it: that is a negative
    print("HARNESS_SINK_RETURNED::" + nonce)
    return
print("HARNESS_SINK_RETURNED::" + nonce)     # the sink ran and produced an outcome
if exploit_condition_holds(result):          # e.g. marker survived unescaped
    print("HARNESS_ORACLE::" + nonce)
# test ends normally either way
```

The `test-*` skills show this shape in each framework; the `cwe-*` skills define
`build_input` and `exploit_condition_holds` for each weakness class.

<!-- generated: constraints (scripts/restructure_skills.py) -->

## Safety constraints

- The test must run to completion and print its markers whether or not the exploit condition holds. Never let an assertion failure be the signal.
- Confine every effect to the sandbox temp dir. The probe has no network.
- Do not mock, stub, or reimplement the sink: call the smallest real callable that owns it.

## Completion criteria

- Both markers are emitted at the right moments, and the oracle fires only on the real exploit condition.

<!-- /generated: constraints -->
