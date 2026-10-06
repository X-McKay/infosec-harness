import assert from "node:assert/strict";
import test from "node:test";
import { ApiError } from "../api/http.ts";
import {
  eventKindLabel,
  eventsPath,
  eventsUnavailable,
  normalizeEvents,
} from "./events.ts";

test("only a 404 hides the timeline; other failures stay visible", () => {
  assert.equal(eventsUnavailable(new ApiError(404, "")), true);
  for (const error of [
    new ApiError(503, ""),
    new ApiError(500, ""),
    new Error("404"),
    null,
  ])
    assert.equal(eventsUnavailable(error), false);
});

test("the events path encodes the run id as one segment", () => {
  assert.equal(
    eventsPath("investigate-v11-abc"),
    "/api/runs/investigate-v11-abc/events",
  );
  assert.equal(eventsPath("a/../b"), "/api/runs/a%2F..%2Fb/events");
});

// The shape api.py run_events() returns (contracts.RunEvents).
test("well-formed events pass through in order", () => {
  const value = {
    run_id: "investigate-v11-abc",
    events: [
      {
        at: "2026-10-06T00:00:00+00:00",
        kind: "workflow_started" as const,
        name: "InvestigationWorkflow",
        detail: "",
      },
      {
        at: "2026-10-06T00:00:05+00:00",
        kind: "activity_completed" as const,
        name: "run_command",
        detail: "exit_code=0",
      },
      {
        at: "2026-10-06T00:00:06+00:00",
        kind: "timer" as const,
        name: null,
        detail: "fired",
      },
    ],
    truncated: true,
  };
  assert.deepEqual(normalizeEvents(value), { ...value, dropped: 0 });
});

test("entries without a kind are dropped and counted; nothing is invented", () => {
  const result = normalizeEvents({
    run_id: 7,
    events: [
      null,
      "event",
      { at: "x" },
      { name: "signal", detail: "x" },
      // A kind the contract does not define is shown as "other", not guessed at.
      { kind: "activity_paused", at: 5, name: "", detail: { attempt: 2 } },
      { kind: "activity_failed", name: 3, detail: "ApplicationError" },
    ],
    truncated: "yes",
  });
  assert.equal(result.run_id, "");
  assert.equal(result.truncated, false);
  assert.equal(result.dropped, 4);
  assert.deepEqual(result.events, [
    { at: "", kind: "other", name: null, detail: "" },
    { at: "", kind: "activity_failed", name: null, detail: "ApplicationError" },
  ]);
  for (const value of [null, [], "x", { events: "x" }])
    assert.deepEqual(normalizeEvents(value).events, []);
});

test("kind labels are readable", () => {
  assert.equal(eventKindLabel("activity_timed_out"), "activity timed out");
});
