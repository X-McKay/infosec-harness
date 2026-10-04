import assert from "node:assert/strict";
import test from "node:test";
import { runActive, batchActive } from "./status.ts";
import { timestamp } from "./format.ts";
test("run and batch polling preserve different unknown-state policies", () => {
  for (const status of ["pending", "accepted", "running", "preparing", "building", "probing", "triaging"]) assert.equal(runActive(status), true);
  for (const status of ["complete", "failed", "cancelled", "needs_info"]) { assert.equal(runActive(status), false); assert.equal(batchActive(status), false); }
  assert.equal(runActive("cancellation_requested"), false);
  assert.equal(batchActive("cancellation_requested"), true);
  assert.equal(runActive("unknown"), false);
  assert.equal(batchActive("unknown"), true);
});
test("recorded timestamps use locale formatting and missing or malformed values stay unavailable", () => {
  for (const value of [null, undefined, "", "invalid", NaN]) assert.equal(timestamp(value), "Unavailable");
  const value = "2026-01-01T00:00:00Z";
  assert.equal(timestamp(value), new Date(value).toLocaleString());
  assert.equal(timestamp(value, "time"), new Date(value).toLocaleTimeString());
  assert.equal(timestamp(0), new Date(0).toLocaleString());
});
