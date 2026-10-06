import assert from "node:assert/strict";
import test from "node:test";
import { ApiError } from "../api/http.ts";
import { eventsPath, eventsUnavailable, normalizeEvents } from "./events.ts";

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

test("well-formed events pass through in order", () => {
  const value = {
    run_id: "investigate-v11-abc",
    events: [
      {
        at: "2026-10-06T00:00:00Z",
        kind: "activity",
        name: "prepare",
        detail: "started",
      },
      {
        at: "2026-10-06T00:00:05Z",
        kind: "workflow",
        name: "completed",
        detail: "",
      },
    ],
    truncated: true,
  };
  assert.deepEqual(normalizeEvents(value), { ...value, dropped: 0 });
});

test("malformed entries are dropped and counted; non-text detail becomes text", () => {
  const result = normalizeEvents({
    run_id: 7,
    events: [
      null,
      "event",
      { at: "x" },
      { kind: "activity", detail: { attempt: 2 } },
      { name: "signal", at: 5, detail: null },
    ],
    truncated: "yes",
  });
  assert.equal(result.run_id, "");
  assert.equal(result.truncated, false);
  assert.equal(result.dropped, 3);
  assert.deepEqual(result.events, [
    { at: "", kind: "activity", name: "", detail: '{"attempt":2}' },
    { at: "", kind: "", name: "signal", detail: "" },
  ]);
  for (const value of [null, [], "x", { events: "x" }])
    assert.deepEqual(normalizeEvents(value).events, []);
});
