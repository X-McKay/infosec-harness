import assert from "node:assert/strict";
import test from "node:test";
import { elapsedSeconds, phaseSummary, workflowCounts } from "./workflow.ts";

test("recorded terminal duration remains fixed, while missing terminal time is unavailable", () => {
  assert.equal(
    elapsedSeconds(
      "2026-01-01T00:00:00Z",
      "2026-01-01T00:01:30Z",
      false,
      Date.parse("2026-02-01"),
    ),
    90,
  );
  assert.equal(
    elapsedSeconds(
      "2026-01-01T00:00:00Z",
      null,
      false,
      Date.parse("2026-02-01"),
    ),
    null,
  );
  assert.equal(
    elapsedSeconds(
      "2026-01-01T00:00:00Z",
      null,
      true,
      Date.parse("2026-01-01T00:00:45Z"),
    ),
    45,
  );
});

test("invalid, reversed and absent timing cannot manufacture elapsed time", () => {
  assert.equal(elapsedSeconds(null, null, true, 0), null);
  assert.equal(elapsedSeconds("invalid", null, true, 0), null);
  assert.equal(elapsedSeconds("2026-01-02", "2026-01-01", false, 0), null);
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
  // An unrecognized run state is not hidden from the totals.
  assert.equal(workflowCounts({ unrecognized: 2 }).active, 2);
});

test("phase labels report recorded counts and omit zero phases without fabricating a stage", () => {
  assert.equal(phaseSummary({}), "Unavailable");
  assert.equal(
    phaseSummary({ environment_planning: 2, probing: 1, complete: 0 }),
    "environment planning: 2 · probing: 1",
  );
});
