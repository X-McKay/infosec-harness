import assert from "node:assert/strict";
import test, { afterEach } from "node:test";
import { QueryClient } from "@tanstack/react-query";
import { parseFindingSearch } from "../lib/search.ts";
import { mutations, queries, queryKeys } from "./queries.ts";

const original = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = original;
});
/** Evaluates a query's polling policy against cached data. */
function interval(options: object, data: unknown): unknown {
  const value = (options as { refetchInterval?: unknown }).refetchInterval;
  return typeof value === "function" ? value({ state: { data } }) : value;
}
const runs = (...statuses: string[]) => ({
  items: statuses.map((status) => ({ status })),
});

test("shared runtime observers use one cache entry", async () => {
  const client = new QueryClient();
  let requests = 0;
  try {
    globalThis.fetch = async () => {
      requests++;
      return Response.json({ environment: "local" });
    };
    const [a, b] = await Promise.all([
      client.fetchQuery(queries.runtime()),
      client.fetchQuery(queries.runtime()),
    ]);
    assert.deepEqual(a, b);
    assert.equal(requests, 1);
  } finally {
    client.clear();
  }
});

test("status and metrics views refresh slowly", () => {
  assert.equal(interval(queries.runtime(), undefined), 30000);
  assert.equal(interval(queries.qualification(), undefined), 30000);
  assert.equal(interval(queries.metrics(), undefined), 60000);
  assert.equal(interval(queries.config(), undefined), undefined);
});

test("evaluation lists and reports poll only while an evaluation is running", () => {
  const list = queries.experiments();
  assert.equal(interval(list, undefined), false);
  assert.equal(interval(list, []), false);
  assert.equal(
    interval(list, [
      { status: "complete" },
      { status: "truncated" },
      { status: null },
    ]),
    false,
  );
  assert.equal(
    interval(list, [{ status: "complete" }, { status: "running" }]),
    10000,
  );
  const detail = queries.experiment("id");
  assert.equal(interval(detail, { metrics: { status: "running" } }), 10000);
  assert.equal(interval(detail, { metrics: { status: "complete" } }), false);
  assert.equal(queries.experiment(undefined).enabled, false);
});

test("finding queries use the run policy, never the batch policy", () => {
  for (const options of [
    queries.runPage(parseFindingSearch({})),
    queries.workflowFindings("batch", 0),
  ]) {
    assert.equal(interval(options, runs("complete", "running")), 2000);
    assert.equal(interval(options, runs("complete", "pending")), 2000);
    assert.equal(interval(options, runs("complete", "failed")), false);
    // Batch-only or unknown states do not keep a run list polling.
    assert.equal(interval(options, runs("cancellation_requested")), false);
  }
  const run = queries.run("id");
  assert.equal(interval(run, { status: "running" }), 2000);
  assert.equal(interval(run, { status: "needs_info" }), false);
  assert.equal(interval(run, undefined), false);
});

test("batch lists keep refreshing for unknown batch states", () => {
  const batches = queries.batches();
  assert.equal(interval(batches, [{ status: "cancellation_requested" }]), 2000);
  assert.equal(interval(batches, [{ status: "complete" }]), 10000);
});

test("review saves to one run and invalidates only that run's cache", async () => {
  const client = new QueryClient();
  const paths: string[] = [];
  try {
    globalThis.fetch = async (path, init) => {
      paths.push(`${init?.method} ${String(path)}`);
      return Response.json({ ok: true });
    };
    client.setQueryData(queryKeys.run("one"), { id: "one" });
    client.setQueryData(queryKeys.run("two"), { id: "two" });
    const review = mutations.review(client, "one");
    await review.mutationFn({
      reviewer: "analyst",
      decision: "confirm",
      reason: "",
    });
    await review.onSuccess();
    assert.deepEqual(paths, ["POST /api/runs/one/review"]);
    assert.equal(
      client.getQueryState(queryKeys.run("one"))?.isInvalidated,
      true,
    );
    assert.equal(
      client.getQueryState(queryKeys.run("two"))?.isInvalidated,
      false,
    );
  } finally {
    client.clear();
  }
});

test("run pages derive API parameters from route filters", async () => {
  const client = new QueryClient();
  const urls: URL[] = [];
  try {
    globalThis.fetch = async (path) => {
      urls.push(new URL(String(path), "http://localhost"));
      return Response.json({ items: [] });
    };
    await client.fetchQuery(
      queries.runPage(
        parseFindingSearch({ verdict: "inconclusive", offset: "50" }),
      ),
    );
    await client.fetchQuery(queries.workflowFindings("batch", 10));
    const [page, workflow] = urls;
    assert.equal(page.pathname, "/api/run-page");
    assert.equal(page.searchParams.get("verdict"), "inconclusive");
    assert.equal(page.searchParams.get("offset"), "50");
    assert.equal(page.searchParams.get("population"), "operational");
    assert.equal(page.searchParams.has("limit"), false);
    assert.equal(workflow.searchParams.get("batch_id"), "batch");
    assert.equal(workflow.searchParams.get("offset"), "10");
    assert.equal(workflow.searchParams.get("limit"), "10");
    assert.equal(workflow.searchParams.get("population"), "operational");
  } finally {
    client.clear();
  }
});
