"use strict";

const test = require("node:test");
const assert = require("node:assert");
const { generateToken } = require("../src/token");

// A deterministic stand-in for Math.random.
function seededRandom(seed) {
  let state = seed >>> 0;
  return function () {
    // LCG (Numerical Recipes constants).
    state = (1664525 * state + 1013904223) >>> 0;
    return state / 4294967296;
  };
}

test("session token and the Math.random stream", () => {
  const original = Math.random;
  try {
    // The same seeded stream is installed both times.
    Math.random = seededRandom(12345);
    const first = generateToken();
    Math.random = seededRandom(12345);
    const second = generateToken();
    assert.strictEqual(first, second);

    // negative control: a different seed yields a different token.
    Math.random = seededRandom(67890);
    assert.notStrictEqual(generateToken(), first);

    // Token format.
    assert.match(first, /^[0-9a-f]{16}$/);
  } finally {
    Math.random = original;
  }
});
