import assert from "node:assert/strict";
import test, { afterEach } from "node:test";
import { QueryClient } from "@tanstack/react-query";
import { ApiError } from "./http.ts";
import {
  ACTIVE_RUN_REFRESH_MS,
  mutations,
  queries,
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
  assert.deepEqual(seen.paths, [
    "/api/health",
    "/api/runs?page_token=tok",
    "/api/runs/investigate-v11-1",
    "/api/runs/investigate-v11-1/events",
    "/api/runs",
    "/api/runs/investigate-v11-1/cancel",
  ]);
  assert.deepEqual(seen.methods, ["GET", "GET", "GET", "GET", "POST", "POST"]);
  client.clear();
});
