import assert from "node:assert/strict";
import test, { afterEach } from "node:test";
import { QueryClient } from "@tanstack/react-query";
import { ApiError } from "./http.ts";
import {
  ACTIVE_RUN_REFRESH_MS,
  fetchHealth,
  mutations,
  queries,
  reportQuery,
  reportsQuery,
  retryUnlessNotFound,
  runPath,
  runRefreshInterval,
  runsPath,
} from "./queries.ts";

const original = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = original;
});
function record(): { paths: string[]; methods: string[] } {
  const seen = { paths: [] as string[], methods: [] as string[] };
  globalThis.fetch = async (path, init) => {
    seen.paths.push(String(path));
    seen.methods.push(init?.method ?? "GET");
    return Response.json({});
  };
  return seen;
}

test("paths stay under /api and encode untrusted ids and tokens", () => {
  assert.equal(runsPath(), "/api/runs");
  assert.equal(runsPath(""), "/api/runs");
  assert.equal(runsPath("a+b/c="), "/api/runs?page_token=a%2Bb%2Fc%3D");
  assert.equal(runPath("investigate-v11-1"), "/api/runs/investigate-v11-1");
  assert.equal(runPath("../health?x"), "/api/runs/..%2Fhealth%3Fx");
});

test("only active runs refresh, at the active interval", () => {
  assert.equal(runRefreshInterval("pending"), ACTIVE_RUN_REFRESH_MS);
  assert.equal(runRefreshInterval("running"), ACTIVE_RUN_REFRESH_MS);
  for (const status of ["completed", "failed", "cancelled", undefined])
    assert.equal(runRefreshInterval(status), false);
});

test("not-found answers are not retried; other failures retry once", () => {
  assert.equal(retryUnlessNotFound(0, new ApiError(404, "")), false);
  assert.equal(retryUnlessNotFound(0, new ApiError(503, "")), true);
  assert.equal(retryUnlessNotFound(1, new ApiError(503, "")), false);
  assert.equal(retryUnlessNotFound(0, new TypeError("network")), true);
});

test("queries and mutations call only their documented endpoints", async () => {
  const seen = record();
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  await client.fetchQuery(queries.health());
  await client.fetchQuery(queries.runs("tok"));
  await client.fetchQuery(queries.run("investigate-v11-1"));
  const events = await client.fetchQuery(
    queries.events("investigate-v11-1", false),
  );
  assert.deepEqual(events.events, []);
  await mutations.submit(client).mutationFn({
    title: "t",
    description: "",
    repo_url: "r",
    revision: "HEAD",
    source_mode: "git_revision",
  });
  await mutations.cancel(client, "investigate-v11-1").mutationFn();
  const reports = await client.fetchQuery(reportsQuery());
  assert.deepEqual(reports, { items: [], truncated: false });
  const report = await client.fetchQuery(reportQuery("model-1.json"));
  assert.equal(report.document.shape, "unknown");
  // A name that is not a report file name never reaches the network.
  await assert.rejects(client.fetchQuery(reportQuery("../settings.json")));
  assert.deepEqual(seen.paths, [
    "/api/health",
    "/api/runs?page_token=tok",
    "/api/runs/investigate-v11-1",
    "/api/runs/investigate-v11-1/events",
    "/api/runs",
    "/api/runs/investigate-v11-1/cancel",
    "/api/reports",
    "/api/reports/model-1.json",
  ]);
  assert.deepEqual(seen.methods, [
    "GET",
    "GET",
    "GET",
    "GET",
    "POST",
    "POST",
    "GET",
    "GET",
  ]);
  client.clear();
});

// api.py health(): 503 with the Health body when Temporal is unreachable.
test("a 503 health body is reported state; other failures stay errors", async () => {
  const unavailable = {
    status: "temporal_unavailable",
    temporal: false,
    runtime: "not_checked",
    generation: "v11",
    task_queue: "investigate-v11",
  };
  globalThis.fetch = async () => Response.json(unavailable, { status: 503 });
  assert.deepEqual(await fetchHealth(), unavailable);
  // A proxy 503 without the Health body, or a 500, is not a health answer.
  globalThis.fetch = async () => new Response("Bad gateway", { status: 503 });
  await assert.rejects(fetchHealth(), ApiError);
  globalThis.fetch = async () =>
    Response.json({ status: "control_plane_ready" }, { status: 503 });
  await assert.rejects(fetchHealth(), ApiError);
  globalThis.fetch = async () => Response.json(unavailable, { status: 500 });
  await assert.rejects(fetchHealth(), ApiError);
});
