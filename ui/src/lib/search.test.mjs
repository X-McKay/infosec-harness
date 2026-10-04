import assert from "node:assert/strict";
import test from "node:test";
import { parseFindingSearch } from "./search.ts";

test("route state retains supported drill-down filters", () => {
  assert.deepEqual(
    parseFindingSearch({
      population: "operational",
      metric: "cost_usd",
      lower: "1.25",
      upper: "2.5",
      upper_inclusive: "true",
      offset: "25",
    }),
    {
      verdict: "",
      batch_id: "",
      search: "",
      offset: 25,
      population: "operational",
      metric: "cost_usd",
      lower: 1.25,
      upper: 2.5,
      upper_inclusive: true,
    },
  );
});

test("route state discards unsupported API enum values", () => {
  const parsed = parseFindingSearch({
    population: "all",
    metric: "accuracy",
  });
  assert.equal(parsed.population, "operational");
  assert.equal(parsed.metric, undefined);
});

test("production filters cannot select non-operational populations", () => {
  for (const population of ["demo", "legacy", "all", "", undefined]) {
    assert.equal(parseFindingSearch({ population }).population, "operational");
  }
});

test("API read methods enforce operational data even for caller overrides", async () => {
  const { api } = await import("../api/client.ts");
  const original = globalThis.fetch;
  const paths = [];
  globalThis.fetch = async (path) => {
    paths.push(path);
    return { ok: true, json: async () => [] };
  };
  try {
    await api.metrics("demo");
    await api.runPage({ population: "demo" });
    await api.runs({ population: "legacy", limit: 25, batch_id: null });
    await api.run("run / id");
    await api.batches();
    await api.batch("batch / id");
    await api.experiments();
    await api.experiment("experiment / id");
    assert.equal(paths.length, 8);
    for (const path of paths) {
      assert.equal(
        new URL(path, "http://test.invalid").searchParams.get("population"),
        "operational",
      );
      assert.doesNotMatch(path, /population=(demo|legacy)/);
    }
    assert.ok(paths.some((path) => path.includes("run%20%2F%20id")));
    const runs = new URL(paths[2], "http://test.invalid");
    assert.equal(runs.searchParams.get("limit"), "25");
    assert.equal(runs.searchParams.has("batch_id"), false);
  } finally {
    globalThis.fetch = original;
  }
});
