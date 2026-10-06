import assert from "node:assert/strict";
import test from "node:test";
import {
  filterRuns,
  hasFilters,
  parseDetailSearch,
  parseInvestigationSearch,
  queueSearch,
  runNeighbors,
  type RunListItem,
} from "./search.ts";

const run = (
  id: string,
  status: string,
  extra: Partial<RunListItem> = {},
): RunListItem => ({
  id,
  title: `Finding ${id}`,
  status,
  started_at: "2026-10-06T00:00:00Z",
  ...extra,
});

test("route state keeps supported filters and the page token", () => {
  assert.deepEqual(
    parseInvestigationSearch({
      q: "  CWE-78 ",
      status: "failed",
      verdict: "inconclusive",
      page: "dG9rZW4=",
    }),
    {
      q: "CWE-78",
      status: "failed",
      verdict: "inconclusive",
      page: "dG9rZW4=",
    },
  );
  assert.deepEqual(parseInvestigationSearch({}), {});
  assert.equal(hasFilters({}), false);
  assert.equal(hasFilters({ page: "x" }), false);
  assert.equal(hasFilters({ q: "x" }), true);
});

test("hostile route state is discarded rather than sent or matched", () => {
  const parsed = parseInvestigationSearch({
    q: 42,
    status: "canceled",
    verdict: "exploitable",
    page: "x".repeat(8193),
    population: "all",
  });
  assert.deepEqual(parsed, {});
  assert.equal(parseInvestigationSearch({ q: "a".repeat(500) }).q?.length, 200);
  assert.equal(
    parseInvestigationSearch({ status: "running" }).status,
    undefined,
  );
});

test("detail URL and return link preserve list state", () => {
  const filters = {
    q: "path traversal",
    status: "completed" as const,
    verdict: "potentially_exploitable" as const,
    page: "cGFnZQ==",
  };
  const detail = parseDetailSearch({ ...filters, from_queue: "true" });
  assert.equal(detail.from_queue, true);
  assert.deepEqual(queueSearch(detail), filters);
  assert.equal(
    parseDetailSearch({ from_queue: "false" }).from_queue,
    undefined,
  );
});

test("filters combine over status group, verdict and text fields", () => {
  const items = [
    run("a", "running"),
    run("b", "completed", { verdict: "inconclusive", cwe: "CWE-22" }),
    run("c", "canceled"),
    run("d", "terminated", { repo_url: "https://example.test/Repo" }),
    run("e", "completed", { verdict: "likely_not_exploitable" }),
  ];
  const ids = (search: Parameters<typeof filterRuns>[1]) =>
    filterRuns(items, search).map((item) => item.id);
  assert.deepEqual(ids({}), ["a", "b", "c", "d", "e"]);
  assert.deepEqual(ids({ status: "active" }), ["a"]);
  assert.deepEqual(ids({ status: "cancelled" }), ["c"]);
  assert.deepEqual(ids({ status: "failed" }), ["d"]);
  assert.deepEqual(ids({ verdict: "inconclusive" }), ["b"]);
  assert.deepEqual(ids({ q: "cwe-22" }), ["b"]);
  assert.deepEqual(ids({ q: "repo" }), ["d"]);
  assert.deepEqual(ids({ q: "finding" }), ["a", "b", "c", "d", "e"]);
  assert.deepEqual(ids({ q: "E", status: "completed" }), ["b", "e"]);
  // A summary without a verdict never matches a verdict filter.
  assert.deepEqual(ids({ verdict: "potentially_exploitable" }), []);
});

test("neighbors come from the same filtered page and are never guessed", () => {
  const items = [{ id: "a" }, { id: "b" }, { id: "c" }];
  assert.deepEqual(runNeighbors("b", items), {
    position: 2,
    total: 3,
    previous: "a",
    next: "c",
  });
  assert.deepEqual(runNeighbors("a", items), {
    position: 1,
    total: 3,
    previous: undefined,
    next: "b",
  });
  assert.deepEqual(runNeighbors("c", items).next, undefined);
  assert.deepEqual(runNeighbors("absent", items), { total: 3 });
  assert.deepEqual(runNeighbors("a", []), { total: 0 });
});
