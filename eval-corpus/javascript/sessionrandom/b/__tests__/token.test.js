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

test("session token and the Math.random stream", () => {
  const original = Math.random;
  try {
    // The same seeded stream is installed both times.
    Math.random = seededRandom(12345);
    const first = generateToken();
    Math.random = seededRandom(12345);
    const second = generateToken();

    // Tokens generated under the same seeded stream.
    assert.notStrictEqual(first, second);
    assert.match(first, /^[0-9a-f]{32}$/);
  } finally {
    Math.random = original;
  }
});
