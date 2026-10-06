import assert from "node:assert/strict";
import test from "node:test";
import {
  duration,
  integer,
  lineCount,
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

test("durations stay in seconds below a minute and never format invalid elapsed time", () => {
  for (const value of [null, undefined, NaN, Infinity, -1])
    assert.equal(duration(value), "Unavailable");
  assert.equal(duration(45), seconds(45));
  assert.equal(duration(0), seconds(0));
  assert.equal(duration(90), "1m 30s");
  assert.equal(duration(3599.9), "59m 59s");
  // 3720 s = 1 h 2 min; seconds are dropped once hours are shown.
  assert.equal(duration(3720), "1h 2m");
  assert.equal(duration(90061), "25h 1m");
});

test("recorded timestamps use locale formatting and missing or malformed values stay unavailable", () => {
  for (const value of [null, undefined, "", "invalid", NaN])
    assert.equal(timestamp(value), "Unavailable");
  const value = "2026-01-01T00:00:00Z";
  assert.equal(timestamp(value), new Date(value).toLocaleString());
  assert.equal(timestamp(value, "time"), new Date(value).toLocaleTimeString());
  assert.equal(timestamp(0), new Date(0).toLocaleString());
});

test("line counts treat a final line break as the end of the last line", () => {
  assert.equal(lineCount(""), 0);
  assert.equal(lineCount("one"), 1);
  assert.equal(lineCount("one\n"), 1);
  // The e2e fixture's probe stdout: three lines, newline-terminated.
  assert.equal(lineCount("a\nb\nc\n"), 3);
  assert.equal(lineCount("a\nb\nc"), 3);
  // A blank line before the final break is still a line.
  assert.equal(lineCount("a\n\n"), 2);
  assert.equal(lineCount("\n"), 1);
  assert.equal(lineCount("a\r\nb\r\n"), 2);
  assert.equal(lineCount("a\rb"), 2);
});
