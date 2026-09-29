---
name: test-jest
description: How to write a probe as a JavaScript or TypeScript test that emits the oracle markers,
  under Jest, Vitest, Mocha or node's built-in test runner. Use this when authoring or repairing a
  probe for a Node repository.
metadata:
  owner: appsec
  version: 1.0.0
---

# Probes in JavaScript and TypeScript (Jest, Vitest, Mocha, `node --test`)

<!-- generated: activation criteria (scripts/restructure_skills.py) -->

## Use this skill when

- You are writing or repairing a probe and the repository's test framework is Jest, Vitest, Mocha, or node's built-in runner (`node --test`).

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

- For a canary oracle, let the payload create `/tmp/harness_canary_<nonce>`; do not assert.

## The body is not portable — declare the test the way your runner provides it

The block above is a **jest** probe. `test(...)` is a global under jest alone, so the same file
fails with `ReferenceError: test is not defined` under vitest (which ships `globals: false`) and
under mocha (whose default BDD interface names it `it`). Measured on all four runners under
node 22. Change one line:

| the repository runs | the line the probe needs | the command |
| --- | --- | --- |
| jest | nothing — `test(...)` is global | `npx jest --silent=false --runTestsByPath {test_file}` |
| vitest | `import { test } from 'vitest';` | `npx vitest run --silent=false {test_file}` |
| mocha | use `it('harness probe', ...)` | `npx mocha {test_file}` |
| `node --test` | `const test = require('node:test');` | `node --test {test_file}` |

- **`--silent=false` is what `-s` is to pytest.** A repository `jest.config.js` or
  `vitest.config.js` carrying `silent: true` replaces the test's console, so all three markers
  vanish *and the run still exits 0*. mocha and node's runner never capture stdout, even behind a
  `json` or `min` reporter, so they need no flag. A jest custom reporter does not swallow console
  output either — only `silent` does.
- **Match the selector to the runner.** `--runTestsByPath` is jest's; vitest rejects it in its own
  argument parser and exits before loading a single file.
- **ESM specifiers keep the extension.** `import { x } from '../src/render.js'` — node's resolver
  does no extension guessing, so the extensionless form dies with `ERR_MODULE_NOT_FOUND` under
  `node --test`. Under jest, importing from a `"type": "module"` package needs
  `NODE_OPTIONS=--experimental-vm-modules`, and a `.require()` of an ESM file fails on every node
  version because jest's own registry does the resolving.
- **TypeScript:** write the probe as `.ts` only if the runner compiles TS. vitest and
  `npx tsx --test` do with no configuration; jest needs `--preset ts-jest` and `@types/jest`
  installed, because ts-jest type-checks the probe and stops on
  `TS2582: Cannot find name 'test'` with `Tests: 0 total`.

## Never skip or disable the probe

**Do not use `test.skip`, `describe.skip`, `it.skip`, `test.todo`, or `test.only` elsewhere in
the file.** A skipped test prints no markers, and Jest reports `No tests found` or a skipped
count — which the harness cannot tell from a probe that is broken. The probe-oracle-protocol
names `No tests found` as a zero-test run, and a zero-test run is never a negative result:
nothing exercised the sink, so it says nothing about exploitability.

Under mocha and `node --test` a skipped probe is worse still: both **exit 0** having run nothing
(`0 passing` / `# pass 0`), so the run is indistinguishable from a clean pass except for the
absent markers. Measured on both.

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
- The probe declares its test function the way its own runner provides it: a bare `test(...)` under jest, `import { test } from 'vitest'` under vitest, `it(...)` under mocha, and `require('node:test')` under node's built-in runner. A bare `test(...)` is a global under jest alone, so the wrong shape is a `ReferenceError` before the sink is ever reached.
- An ESM specifier keeps the file extension (`../src/render.js`, not `../src/render`): node's own resolver does no extension guessing, so the extensionless form fails with `ERR_MODULE_NOT_FOUND` under `node --test`.

<!-- /generated: constraints -->
