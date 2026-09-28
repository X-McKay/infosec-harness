---
name: test-jest
description: How to write a probe as a Jest or Vitest test that emits the oracle markers. Use this
  when authoring or repairing a probe for a Jest repository.
metadata:
  owner: appsec
  version: 1.0.0
---

# Probes in Jest / Vitest

<!-- generated: activation criteria (scripts/restructure_skills.py) -->

## Use this skill when

- You are writing or repairing a probe and the repository's test framework is Jest or Vitest.

## Do not use this skill when

- The repository uses a different framework; load that `test-*` skill.
- You have not yet read `probe-oracle-protocol`; read it first.

<!-- /generated: activation criteria -->

- Place the file at the planned path (e.g. `__tests__/harness_probe_<id>.test.js`) so it can
  import the code under test; use the repo's TS setup if needed.
- Inline the nonce. Use `console.log` for markers; do not rely on `expect`.

```js
test('harness probe', async () => {
  const NONCE = '<nonce>';
  const { targetCallable } = require('../src/module');   // the real sink owner
  const payload = buildInput(NONCE);                     // per the cwe-* skill
  console.log(`HARNESS_PRECONDITION::${NONCE}`);         // about to call the sink
  let result;
  try {
    result = await targetCallable(payload);
  } catch (err) {
    if (!isTargetRejectedInput(err)) throw err;          // a real defect: fail loudly
    console.log(`HARNESS_SINK_RETURNED::${NONCE}`);      // the code refused it: a negative
    return;
  }
  console.log(`HARNESS_SINK_RETURNED::${NONCE}`);        // the sink ran and returned
  if (exploitConditionHolds(result, NONCE)) {
    console.log(`HARNESS_ORACLE::${NONCE}`);
  }
});
```

- Run with `npx jest --runTestsByPath {test_file}` (or `npx vitest run {test_file}`).
- For a canary oracle, let the payload create `/tmp/harness_canary_<nonce>`; do not assert.

## Never skip or disable the probe

**Do not use `test.skip`, `describe.skip`, `it.skip`, `test.todo`, or `test.only` elsewhere in
the file.** A skipped test prints no markers, and Jest reports `No tests found` or a skipped
count — which the harness cannot tell from a probe that is broken. The probe-oracle-protocol
names `No tests found` as a zero-test run, and a zero-test run is never a negative result:
nothing exercised the sink, so it says nothing about exploitability.

`test.only` is the subtler hazard, because it does not look like skipping: it silently excludes
every *other* test in the file, so a probe placed after one never runs and the run still exits
0. If a module the probe needs is absent, let the `require` throw: the error naming the missing
module is an *environment* signal that build repair can act on.

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
