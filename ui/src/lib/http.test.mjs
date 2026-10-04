import assert from "node:assert/strict";
import test from "node:test";
import { ApiError, req } from "../api/http.ts";
test("HTTP failures retain status without classifying network errors as not-found", async () => {
 const original = globalThis.fetch;
 try {
  globalThis.fetch = async () => new Response("missing", {status: 404});
  await assert.rejects(req("/api/runs/absent"), e => e instanceof ApiError && e.status === 404 && e.message === "404 missing");
  globalThis.fetch = async () => { throw new Error("404-like network message"); };
  await assert.rejects(req("/api/runs/absent"), e => !(e instanceof ApiError));
 } finally { globalThis.fetch = original; }
});
test("JSON transport preserves successful response and mutation request", async () => {
 const original = globalThis.fetch;
 try {
  globalThis.fetch = async (path, init) => {
   assert.equal(path, "/api/runs/id/review"); assert.equal(init.method, "POST");
   assert.equal(init.headers["Content-Type"], "application/json"); assert.equal(init.body, '{"decision":"confirm"}');
   return Response.json({saved: true});
  };
  assert.deepEqual(await req("/api/runs/id/review", {method: "POST", body: '{"decision":"confirm"}'}), {saved: true});
 } finally { globalThis.fetch = original; }
});
