import assert from "node:assert/strict";
import test from "node:test";
import { parseFindingSearch, parseFindingDetailSearch, queueSearch, findingPageQuery, findingNeighbors } from "./search.ts";

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


test("detail URL and return link preserve queue filters and operational population", () => {
  const filters = { verdict: "inconclusive", batch_id: "batch-27", search: "CWE-78 & command", offset: 50, metric: "total_tokens", lower: 100, upper: 200, upper_inclusive: true };
  const detail = parseFindingDetailSearch({ ...filters, population: "demo", from_queue: "true" });
  assert.equal(detail.from_queue, true);
  assert.deepEqual(queueSearch(detail), { ...filters, population: "operational" });
  assert.deepEqual(findingPageQuery(queueSearch(detail)), { ...filters, population: "operational" });
  assert.equal(parseFindingDetailSearch({}).from_queue, false);
  assert.equal(parseFindingDetailSearch({ from_queue: "false" }).from_queue, false);
});

test("hostile numeric route state cannot send nonfinite bounds or invalid offsets", () => {
  for (const offset of ["Infinity", "-5", "2.5", "bad", Number.MAX_SAFE_INTEGER + 1]) {
    assert.equal(parseFindingSearch({ offset }).offset, 0);
  }
  const filters = parseFindingSearch({ lower: "NaN", upper: "Infinity" });
  assert.equal(filters.lower, undefined);
  assert.equal(filters.upper, undefined);
});

test("neighbors come from the same filtered page without extra requests", async () => {
  const requests = [];
  const search = parseFindingSearch({ offset: 25, batch_id: "selected", search: "needle", metric: "cost_usd", upper: 1.5 });
  const result = await findingNeighbors("current", search, async (query) => {
    requests.push(query);
    return { items: [{ id: "before" }, { id: "current" }, { id: "after" }], offset: 25, limit: 25, total: 99 };
  });
  assert.deepEqual(result, { position: 27, total: 99, previous: { id: "before", offset: 25 }, next: { id: "after", offset: 25 } });
  assert.deepEqual(requests, [findingPageQuery(search)]);
});

test("first finding on a later page links to the previous filtered page", async () => {
  const requests = [];
  const search = parseFindingSearch({ offset: 25, verdict: "inconclusive", lower: 2, metric: "wall_time_s" });
  const result = await findingNeighbors("current", search, async (query) => {
    requests.push(query);
    return query.offset === 25
      ? { items: [{ id: "current" }, { id: "next" }], offset: 25, limit: 25, total: 27 }
      : { items: [{ id: "previous" }], offset: 0, limit: 25, total: 27 };
  });
  assert.deepEqual(result.previous, { id: "previous", offset: 0 });
  assert.deepEqual(result.next, { id: "next", offset: 25 });
  assert.deepEqual(requests[1], { ...findingPageQuery(search), offset: 0, limit: 25 });
});

test("last finding on a page links to the next filtered page", async () => {
  const requests = [];
  const search = parseFindingSearch({ batch_id: "selected", metric: "output_tokens", upper: 100, upper_inclusive: true });
  const items = Array.from({ length: 25 }, (_, index) => ({ id: String(index) }));
  const result = await findingNeighbors("24", search, async (query) => {
    requests.push(query);
    return query.offset === 0
      ? { items, offset: 0, limit: 25, total: 26 }
      : { items: [{ id: "25" }], offset: 25, limit: 25, total: 26 };
  });
  assert.deepEqual(result.next, { id: "25", offset: 25 });
  assert.deepEqual(requests[1], { ...findingPageQuery(search), offset: 25, limit: 25 });
});

test("changed membership or end of queue never guesses a neighboring finding", async () => {
  const search = parseFindingSearch({});
  assert.deepEqual(await findingNeighbors("absent", search, async () => ({ items: [{ id: "other" }], offset: 0, limit: 25, total: 1 })), { total: 1 });
  const only = await findingNeighbors("only", search, async () => ({ items: [{ id: "only" }], offset: 0, limit: 25, total: 1 }));
  assert.deepEqual(only, { position: 1, total: 1, previous: undefined, next: undefined });
  await assert.rejects(findingNeighbors("only", search, async () => { throw new Error("API unavailable"); }), /API unavailable/);
});


test("non-aligned offsets fetch only the exact preceding range", async () => {
  const requests = [];
  const search = parseFindingSearch({ offset: 10, batch_id: "selected" });
  const all = Array.from({ length: 40 }, (_, index) => ({ id: String(index) }));
  const result = await findingNeighbors("10", search, async (query) => {
    requests.push(query);
    const limit = query.limit ?? 25;
    return { items: all.slice(query.offset, query.offset + limit), offset: query.offset, limit, total: all.length };
  });
  assert.deepEqual(result.previous, { id: "9", offset: 0 });
  assert.deepEqual(result.next, { id: "11", offset: 10 });
  assert.deepEqual(requests[1], { ...findingPageQuery(search), offset: 0, limit: 10 });
});
