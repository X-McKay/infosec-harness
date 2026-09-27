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
  console.log(`HARNESS_PRECONDITION::${NONCE}`);         // reached the sink
  const result = await targetCallable(payload);
  if (exploitConditionHolds(result, NONCE)) {
    console.log(`HARNESS_ORACLE::${NONCE}`);
  }
});
```

- Run with `npx jest --runTestsByPath {test_file}` (or `npx vitest run {test_file}`).
- For a canary oracle, let the payload create `/tmp/harness_canary_<nonce>`; do not assert.

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
