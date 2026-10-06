import assert from "node:assert/strict";
import test from "node:test";
import { apiBase, healthPresentation, readable } from "./runtime.ts";

// api.py health() today.
test("the current health response reports the generation and leaves the runtime not checked", () => {
  assert.deepEqual(
    healthPresentation({
      status: "control_plane_ready",
      runtime: "not_checked",
      generation: "v11",
    }),
    {
      status: "control_plane_ready",
      temporal: null,
      runtime: "not_checked",
      generation: "v11",
      taskQueue: null,
      other: [],
    },
  );
});

// The extended response: {status, temporal, generation, task_queue}.
test("an extended response shows its task queue, and an absent runtime is not checked", () => {
  const health = healthPresentation({
    status: "ok",
    temporal: "reachable",
    generation: "v11",
    task_queue: "investigate-v11",
    build: "abc",
  });
  assert.equal(health.taskQueue, "investigate-v11");
  assert.equal(health.temporal, "reachable");
  assert.equal(health.runtime, "not_checked");
  assert.deepEqual(health.other, [["build", "abc"]]);
});

test("malformed responses never produce reported values", () => {
  for (const value of [
    null,
    undefined,
    "ok",
    [],
    { status: 1, runtime: true },
  ]) {
    const health = healthPresentation(value);
    assert.equal(health.status, null);
    assert.equal(health.generation, null);
    assert.equal(health.runtime, "not_checked");
  }
  assert.equal(readable(null), "Not reported");
  assert.equal(readable("control_plane_ready"), "control plane ready");
});

test("the API base is the same origin", () => {
  assert.equal(apiBase("http://localhost:8080"), "http://localhost:8080/api");
  assert.equal(apiBase("https://harness.test/"), "https://harness.test/api");
});
