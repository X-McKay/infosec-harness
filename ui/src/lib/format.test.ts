import assert from "node:assert/strict";
import test from "node:test";
import {
  integer,
  money,
  number,
  percent,
  seconds,
  timestamp,
} from "./format.ts";

test("every formatter renders missing measurements as unavailable", () => {
  for (const format of [number, integer, money, seconds, percent])
    for (const value of [null, undefined])
      assert.equal(format(value), "Unavailable");
});

test("percentages keep fixed precision and never coerce absent fractions to zero", () => {
  assert.equal(percent(0.756), "75.6%");
  assert.equal(percent(0.75), "75.0%");
  assert.equal(percent(0.5, 0), "50%");
  assert.equal(percent(0), "0.0%");
});

test("recorded timestamps use locale formatting and missing or malformed values stay unavailable", () => {
  for (const value of [null, undefined, "", "invalid", NaN])
    assert.equal(timestamp(value), "Unavailable");
  const value = "2026-01-01T00:00:00Z";
  assert.equal(timestamp(value), new Date(value).toLocaleString());
  assert.equal(timestamp(value, "time"), new Date(value).toLocaleTimeString());
  assert.equal(timestamp(0), new Date(0).toLocaleString());
});
