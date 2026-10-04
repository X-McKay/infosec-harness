import assert from "node:assert/strict";
import test from "node:test";
import {
  elapsedSeconds,
  workflowCounts,
  phaseSummary,
  workflowActive,
} from "./workflow.ts";

test("recorded terminal duration remains fixed, while missing terminal time is unavailable", () => {
  assert.equal(
    elapsedSeconds(
      "2026-01-01T00:00:00Z",
      "2026-01-01T00:01:30Z",
      "complete",
      Date.parse("2026-02-01"),
    ),
    90,
  );
  assert.equal(
    elapsedSeconds(
      "2026-01-01T00:00:00Z",
      null,
      "complete",
      Date.parse("2026-02-01"),
    ),
    null,
  );
  assert.equal(
    elapsedSeconds(
      "2026-01-01T00:00:00Z",
      null,
      "running",
      Date.parse("2026-01-01T00:00:45Z"),
    ),
    45,
  );
});

test("invalid, reversed and absent timing cannot manufacture elapsed time", () => {
  assert.equal(elapsedSeconds(null, null, "running", 0), null);
  assert.equal(elapsedSeconds("invalid", null, "running", 0), null);
  assert.equal(elapsedSeconds("2026-01-02", "2026-01-01", "failed", 0), null);
});

test("completion is distinct from failures, cancellation and needs-info", () => {
  assert.deepEqual(
    workflowCounts({
      complete: 2,
      failed: 1,
      cancelled: 3,
      needs_info: 4,
      running: 5,
      pending: 6,
    }),
    { complete: 2, failed: 1, cancelled: 3, needsInfo: 4, active: 11 },
  );
  assert.equal(workflowActive("cancellation_requested"), true);
  assert.equal(workflowActive("needs_info"), false);
});

test("phase labels report recorded counts and omit zero phases without fabricating a stage", () => {
  assert.equal(phaseSummary({}), "Unavailable");
  assert.equal(
    phaseSummary({ environment_planning: 2, probing: 1, complete: 0 }),
    "environment planning: 2 · probing: 1",
  );
});
