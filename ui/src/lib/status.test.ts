import assert from "node:assert/strict";
import test from "node:test";
import {
  runActive,
  statusGroup,
  statusLabel,
  statusVariant,
  terminal,
} from "./status.ts";

// RunState.status in contracts.py: pending, running, completed, failed, cancelled.
// Workflow phase names (queued, finished, ...) are never a run status.
test("only pending and running investigations are active and keep polling", () => {
  for (const status of ["pending", "running"]) {
    assert.equal(runActive(status), true);
    assert.equal(terminal(status), false);
  }
  for (const status of ["completed", "failed", "cancelled"]) {
    assert.equal(runActive(status), false);
    assert.equal(terminal(status), true);
  }
  for (const phase of ["queued", "finished", "investigating", "", null])
    assert.equal(runActive(phase), false);
});

// RunSummary.status in api.py is WorkflowExecutionStatus.name.lower(); api.py run() reports
// TERMINATED and TIMED_OUT executions as "failed" and CANCELED as "cancelled".
test("Temporal list statuses group the same way the detail endpoint reports them", () => {
  assert.equal(statusGroup("canceled"), "cancelled");
  assert.equal(statusGroup("terminated"), "failed");
  assert.equal(statusGroup("timed_out"), "failed");
  assert.equal(statusGroup("completed"), "completed");
  assert.equal(statusGroup("running"), "active");
  assert.equal(statusLabel("canceled"), "cancelled");
  assert.equal(statusLabel("timed_out"), "timed out");
});

test("unrecognized statuses are neither active nor terminal and are shown as recorded", () => {
  for (const status of ["continued_as_new", "unknown", "Running", undefined]) {
    assert.equal(statusGroup(status), "unknown");
    assert.equal(runActive(status), false);
    assert.equal(terminal(status), false);
    assert.equal(statusVariant(status), "muted");
  }
  assert.equal(statusLabel("continued_as_new"), "continued as new");
  assert.equal(statusLabel(undefined), "unknown");
});

test("failure never shares a badge with success or activity", () => {
  assert.equal(statusVariant("terminated"), "failed");
  assert.equal(statusVariant("completed"), "outline");
  assert.equal(statusVariant("pending"), "active");
});
