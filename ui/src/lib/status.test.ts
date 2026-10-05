import assert from "node:assert/strict";
import test from "node:test";
import {
  batchActive,
  experimentActive,
  runActive,
  terminal,
} from "./status.ts";

// Backend lifecycle (persistence/lifecycle.py): a run is stored as pending, then running,
// then a terminal value. Workflow phase names are telemetry, never a run status.
test("run polling recognizes only the recorded pending and running states", () => {
  for (const status of ["pending", "running"])
    assert.equal(runActive(status), true);
  for (const phase of [
    "accepted",
    "preparing",
    "building",
    "probing",
    "triaging",
  ])
    assert.equal(runActive(phase), false);
  assert.equal(runActive("unknown"), false);
});

test("terminal states end run and batch activity; unknown batch states keep refreshing", () => {
  for (const status of ["complete", "failed", "cancelled", "needs_info"]) {
    assert.equal(terminal(status), true);
    assert.equal(runActive(status), false);
    assert.equal(batchActive(status), false);
  }
  for (const status of [
    "accepted",
    "running",
    "cancellation_requested",
    "unknown",
  ])
    assert.equal(batchActive(status), true);
  assert.equal(runActive("cancellation_requested"), false);
});

// Evaluation runs persist running, truncated or complete (evals/run.py).
test("only a running evaluation is active", () => {
  assert.equal(experimentActive("running"), true);
  for (const status of [
    "complete",
    "truncated",
    "pending",
    "queued",
    undefined,
    null,
    1,
  ])
    assert.equal(experimentActive(status), false);
});
