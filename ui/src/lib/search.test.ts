import assert from "node:assert/strict";
import test from "node:test";
import type { RunPageQuery } from "../api/client.ts";
import {
  findingNeighbors,
  findingPageQuery,
  histogramSearch,
  parseFindingDetailSearch,
  parseFindingSearch,
  queueSearch,
} from "./search.ts";

type Page = Awaited<
  Parameters<typeof findingNeighbors>[2] extends (
    query: RunPageQuery,
  ) => Promise<infer P>
    ? P
    : never
>;
const ids = (...values: string[]) => values.map((id) => ({ id }));

test("route state retains supported drill-down filters", () => {
  assert.deepEqual(
    parseFindingSearch({
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
      metric: "cost_usd",
      lower: 1.25,
      upper: 2.5,
      upper_inclusive: true,
    },
  );
});

test("route state discards unsupported metrics and any population", () => {
  for (const population of ["demo", "legacy", "all", "operational"]) {
    const parsed = parseFindingSearch({ population, metric: "accuracy" });
    assert.equal(parsed.metric, undefined);
    assert.equal("population" in parsed, false);
    assert.equal("population" in findingPageQuery(parsed), false);
  }
});

test("detail URL and return link preserve queue filters", () => {
  const filters = {
    verdict: "inconclusive",
    batch_id: "batch-27",
    search: "CWE-78 & command",
    offset: 50,
    metric: "total_tokens" as const,
    lower: 100,
    upper: 200,
    upper_inclusive: true,
  };
  const detail = parseFindingDetailSearch({
    ...filters,
    population: "demo",
    from_queue: "true",
  });
  assert.equal(detail.from_queue, true);
  assert.deepEqual(queueSearch(detail), filters);
  assert.deepEqual(findingPageQuery(queueSearch(detail)), filters);
  assert.equal(parseFindingDetailSearch({}).from_queue, false);
  assert.equal(
    parseFindingDetailSearch({ from_queue: "false" }).from_queue,
    false,
  );
});

test("hostile numeric route state cannot send nonfinite bounds or invalid offsets", () => {
  for (const offset of [
    "Infinity",
    "-5",
    "2.5",
    "bad",
    Number.MAX_SAFE_INTEGER + 1,
  ]) {
    assert.equal(parseFindingSearch({ offset }).offset, 0);
  }
  const filters = parseFindingSearch({ lower: "NaN", upper: "Infinity" });
  assert.equal(filters.lower, undefined);
  assert.equal(filters.upper, undefined);
});

test("histogram drill-down filters one bin and includes only the final upper edge", () => {
  const bin = { lower: 1, upper: 2 };
  assert.deepEqual(histogramSearch("cost_usd", bin, false), {
    verdict: "",
    batch_id: "",
    search: "",
    offset: 0,
    metric: "cost_usd",
    lower: 1,
    upper: 2,
    upper_inclusive: false,
  });
  assert.equal(histogramSearch("cost_usd", bin, true).upper_inclusive, true);
  // The drill-down survives the route parser unchanged.
  const search = histogramSearch("wall_time_s", bin, true);
  assert.deepEqual(parseFindingSearch({ ...search }), search);
});

test("neighbors come from the same filtered page without extra requests", async () => {
  const requests: RunPageQuery[] = [];
  const search = parseFindingSearch({
    offset: 25,
    batch_id: "selected",
    search: "needle",
    metric: "cost_usd",
    upper: 1.5,
  });
  const result = await findingNeighbors("current", search, async (query) => {
    requests.push(query);
    return {
      items: ids("before", "current", "after"),
      offset: 25,
      limit: 25,
      total: 99,
    };
  });
  assert.deepEqual(result, {
    position: 27,
    total: 99,
    previous: { id: "before", offset: 25 },
    next: { id: "after", offset: 25 },
  });
  assert.deepEqual(requests, [findingPageQuery(search)]);
});

test("first finding on a later page links to the previous filtered page", async () => {
  const requests: RunPageQuery[] = [];
  const search = parseFindingSearch({
    offset: 25,
    verdict: "inconclusive",
    lower: 2,
    metric: "wall_time_s",
  });
  const result = await findingNeighbors("current", search, async (query) => {
    requests.push(query);
    return query.offset === 25
      ? { items: ids("current", "next"), offset: 25, limit: 25, total: 27 }
      : { items: ids("previous"), offset: 0, limit: 25, total: 27 };
  });
  assert.deepEqual(result.previous, { id: "previous", offset: 0 });
  assert.deepEqual(result.next, { id: "next", offset: 25 });
  assert.deepEqual(requests[1], {
    ...findingPageQuery(search),
    offset: 0,
    limit: 25,
  });
});

test("last finding on a page links to the next filtered page", async () => {
  const requests: RunPageQuery[] = [];
  const search = parseFindingSearch({
    batch_id: "selected",
    metric: "output_tokens",
    upper: 100,
    upper_inclusive: true,
  });
  const items = Array.from({ length: 25 }, (_, index) => ({
    id: String(index),
  }));
  const result = await findingNeighbors("24", search, async (query) => {
    requests.push(query);
    return query.offset === 0
      ? { items, offset: 0, limit: 25, total: 26 }
      : { items: ids("25"), offset: 25, limit: 25, total: 26 };
  });
  assert.deepEqual(result.next, { id: "25", offset: 25 });
  assert.deepEqual(requests[1], {
    ...findingPageQuery(search),
    offset: 25,
    limit: 25,
  });
});

test("changed membership or end of queue never guesses a neighboring finding", async () => {
  const search = parseFindingSearch({});
  const single = (id: string): Page => ({
    items: ids(id),
    offset: 0,
    limit: 25,
    total: 1,
  });
  assert.deepEqual(
    await findingNeighbors("absent", search, async () => single("other")),
    { total: 1 },
  );
  assert.deepEqual(
    await findingNeighbors("only", search, async () => single("only")),
    { position: 1, total: 1, previous: undefined, next: undefined },
  );
  await assert.rejects(
    findingNeighbors("only", search, async () => {
      throw new Error("API unavailable");
    }),
    /API unavailable/,
  );
});

test("non-aligned offsets fetch only the exact preceding range", async () => {
  const requests: RunPageQuery[] = [];
  const search = parseFindingSearch({ offset: 10, batch_id: "selected" });
  const all = Array.from({ length: 40 }, (_, index) => ({ id: String(index) }));
  const result = await findingNeighbors("10", search, async (query) => {
    requests.push(query);
    const offset = query.offset ?? 0;
    const limit = query.limit ?? 25;
    return {
      items: all.slice(offset, offset + limit),
      offset,
      limit,
      total: all.length,
    };
  });
  assert.deepEqual(result.previous, { id: "9", offset: 0 });
  assert.deepEqual(result.next, { id: "11", offset: 10 });
  assert.deepEqual(requests[1], {
    ...findingPageQuery(search),
    offset: 0,
    limit: 10,
  });
});
