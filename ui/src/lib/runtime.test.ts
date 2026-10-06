import assert from "node:assert/strict";
import test from "node:test";
import {
  apiBase,
  healthPresentation,
  readable,
  temporalLabel,
} from "./runtime.ts";

// api.py health() with Temporal reachable (200).
test("a ready control plane reports its queue and leaves the runtime not checked", () => {
  assert.deepEqual(
    healthPresentation({
      status: "control_plane_ready",
      temporal: true,
      runtime: "not_checked",
      generation: "v11",
      task_queue: "investigate-v11",
    }),
    {
      status: "control_plane_ready",
      temporal: true,
      runtime: "not_checked",
      generation: "v11",
      taskQueue: "investigate-v11",
      ready: true,
    },
  );
});

// api.py health() answers 503 with the same shape when Temporal is unreachable.
test("an unreachable Temporal is never ready", () => {
  const health = healthPresentation({
    status: "temporal_unavailable",
    temporal: false,
    runtime: "not_checked",
    generation: "v11",
    task_queue: "investigate-v11",
  });
  assert.equal(health.ready, false);
  assert.equal(temporalLabel(health.temporal), "unreachable");
  // A ready status without a reported Temporal check is not ready either.
  assert.equal(
    healthPresentation({ status: "control_plane_ready" }).ready,
    false,
  );
});

test("malformed responses never produce reported values", () => {
  for (const value of [
    null,
    undefined,
    "ok",
    [],
    { status: 1, runtime: true, temporal: "yes" },
    { status: "ok", temporal: "reachable" },
  ]) {
    const health = healthPresentation(value);
    assert.equal(health.status, null);
    assert.equal(health.temporal, null);
    assert.equal(health.generation, null);
    assert.equal(health.runtime, "not_checked");
    assert.equal(health.ready, false);
  }
  assert.equal(temporalLabel(null), "Not reported");
  assert.equal(readable(null), "Not reported");
  assert.equal(readable("control_plane_ready"), "control plane ready");
});

test("the API base is the same origin", () => {
  assert.equal(apiBase("http://localhost:8080"), "http://localhost:8080/api");
  assert.equal(apiBase("https://harness.test/"), "https://harness.test/api");
});
