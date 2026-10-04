import assert from "node:assert/strict";
import test from "node:test";
import {
  brokerPresentation,
  componentTitle,
  connectivityPresentation,
  modelNames,
} from "./runtime.ts";

test("unconfigured broker suppresses stale and unresolved retained observations", () => {
  assert.deepEqual(
    brokerPresentation({
      configured: false,
      status: "failed",
      stale: true,
      unresolved_requests: 16,
    }),
    { label: "Not enabled", stale: false, unresolved: null },
  );
});
test("configured broker retains measured warnings", () => {
  assert.deepEqual(
    brokerPresentation({
      configured: true,
      status: "not_checked",
      stale: true,
      unresolved_requests: 16,
    }),
    { label: "not checked", stale: true, unresolved: 16 },
  );
});
test("configured names never imply measured connectivity", () => {
  assert.equal(modelNames(["local/model"]), "local/model");
  assert.equal(connectivityPresentation(undefined).status, "not_checked");
  assert.equal(
    connectivityPresentation({
      status: "passed",
      checked_at: null,
      detail: "No observation",
    }).status,
    "not_checked",
  );
  assert.match(modelNames([]), /unavailable/);
});
test("recorded failed and passed connectivity remain distinct", () => {
  for (const status of ["failed", "passed"]) {
    const result = connectivityPresentation({
      status,
      checked_at: "2026-10-04T15:00:00Z",
      detail: "Measured observation",
    });
    assert.equal(result.status, status);
    assert.equal(result.checkedAt, "2026-10-04T15:00:00Z");
  }
});
test("retained component pass is labelled only as component evidence", () => {
  assert.equal(componentTitle("passed"), "Component evidence passed");
  assert.equal(componentTitle("not_checked"), "Component evidence");
});
