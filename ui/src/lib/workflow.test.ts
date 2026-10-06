import assert from "node:assert/strict";
import test from "node:test";
import { elapsedSeconds, phaseLabel, statusCounts } from "./workflow.ts";

// RunSummary carries started_at and, once closed, closed_at (api.py runs()).
test("recorded closed duration remains fixed, while missing close time is unavailable", () => {
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
  // A recorded close time wins over the clock even while the list still says active.
  assert.equal(
    elapsedSeconds(
      "2026-01-01T00:00:00Z",
      "2026-01-01T00:00:10Z",
      true,
      Date.parse("2026-03-01"),
    ),
    10,
  );
});

test("invalid, reversed and absent timing cannot manufacture elapsed time", () => {
  assert.equal(elapsedSeconds(null, null, true, 0), null);
  assert.equal(elapsedSeconds("invalid", null, true, 0), null);
  assert.equal(elapsedSeconds("2026-01-02", "2026-01-01", false, 0), null);
  assert.equal(
    elapsedSeconds(
      "2026-01-01T00:00:00Z",
      null,
      true,
      Date.parse("2025-12-31"),
    ),
    null,
  );
});

test("page counts keep failures, cancellations and unknown states distinct", () => {
  assert.deepEqual(
    statusCounts(
      [
        "running",
        "completed",
        "completed",
        "failed",
        "terminated",
        "timed_out",
        "canceled",
        "continued_as_new",
      ].map((status) => ({ status })),
    ),
    { active: 1, completed: 2, failed: 3, cancelled: 1, unknown: 1 },
  );
  assert.deepEqual(statusCounts([]), {
    active: 0,
    completed: 0,
    failed: 0,
    cancelled: 0,
    unknown: 0,
  });
});

test("phase labels are readable and never fabricate a stage", () => {
  assert.equal(phaseLabel("queued"), "queued");
  assert.equal(phaseLabel("source_capture"), "source capture");
  assert.equal(phaseLabel(""), "Unavailable");
  assert.equal(phaseLabel(undefined), "Unavailable");
});
