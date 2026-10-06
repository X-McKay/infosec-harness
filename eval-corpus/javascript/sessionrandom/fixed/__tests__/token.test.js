"use strict";

const test = require("node:test");
const assert = require("node:assert");
const { generateToken } = require("../src/token");

function seededRandom(seed) {
  let state = seed >>> 0;
  return function () {
    state = (1664525 * state + 1013904223) >>> 0;
    return state / 4294967296;
  };
}

test("session token is not predictable from the Math.random stream", () => {
  const original = Math.random;
  try {
    // Same weak stream installed both times, yet the CSPRNG-based tokens differ.
    Math.random = seededRandom(12345);
    const first = generateToken();
    Math.random = seededRandom(12345);
    const second = generateToken();

    // FIXED: reproducing Math.random does not reproduce the token.
    assert.notStrictEqual(first, second);
    assert.match(first, /^[0-9a-f]{32}$/);
  } finally {
    Math.random = original;
  }
});
