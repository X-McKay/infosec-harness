import assert from "node:assert/strict";
import test, { afterEach } from "node:test";
import { api, type RunPageQuery } from "./client.ts";

const original = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = original;
});
function record(): string[] {
  const paths: string[] = [];
  globalThis.fetch = async (path) => {
    paths.push(String(path));
    return Response.json([]);
  };
  return paths;
}

test("API read methods enforce operational data even for caller overrides", async () => {
  const paths = record();
  // A hostile or untyped caller cannot select another population.
  const override = { population: "demo" } as RunPageQuery;
  await api.metrics();
  await api.runPage(override);
  await api.runPage({ ...override, limit: 25, batch_id: null });
  await api.run("run / id");
  await api.batches();
  await api.experiments();
  await api.experiment("experiment / id");
  assert.equal(paths.length, 7);
  for (const path of paths) {
    const url = new URL(path, "http://test.invalid");
    assert.deepEqual(url.searchParams.getAll("population"), ["operational"]);
  }
  assert.ok(paths.some((path) => path.includes("run%20%2F%20id")));
  assert.ok(paths.some((path) => path.includes("experiment%20%2F%20id")));
  const page = new URL(paths[2], "http://test.invalid");
  assert.equal(page.searchParams.get("limit"), "25");
  assert.equal(page.searchParams.has("batch_id"), false);
});

test("unscoped status reads and review writes carry no population parameter", async () => {
  const paths = record();
  await api.runtimeStatus();
  await api.qualification();
  await api.config();
  await api.review("run / id", {
    reviewer: "analyst",
    decision: "confirm",
    reason: "",
  });
  assert.deepEqual(paths, [
    "/api/runtime-status",
    "/api/qualification",
    "/api/config",
    "/api/runs/run%20%2F%20id/review",
  ]);
});
