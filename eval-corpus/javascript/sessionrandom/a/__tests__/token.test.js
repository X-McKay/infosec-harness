"use strict";

const test = require("node:test");
const assert = require("node:assert");
const { generateToken } = require("../src/token");

// A deterministic stand-in for Math.random so the probe can reproduce the stream an
// attacker would recover from a non-cryptographic PRNG.
function seededRandom(seed) {
  let state = seed >>> 0;
  return function () {
    // LCG (Numerical Recipes constants).
    state = (1664525 * state + 1013904223) >>> 0;
    return state / 4294967296;
  };
}

test("session token is predictable from the Math.random stream", () => {
  const original = Math.random;
  try {
    // positive control: a known weak stream reproduces the same token twice.
    Math.random = seededRandom(12345);
    const first = generateToken();
    Math.random = seededRandom(12345);
    const second = generateToken();
    assert.strictEqual(first, second);

    // negative control: a different seed yields a different token.
    Math.random = seededRandom(67890);
    assert.notStrictEqual(generateToken(), first);

    // VULNERABLE: the real generator's output is fully determined by the PRNG stream.
    assert.match(first, /^[0-9a-f]{16}$/);
  } finally {
    Math.random = original;
  }
});
