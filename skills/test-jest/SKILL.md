---
name: test-jest
description: "How to write a probe as a Jest/Vitest test that emits the oracle markers."
---

# Probes in Jest / Vitest

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
