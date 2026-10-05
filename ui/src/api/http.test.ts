import assert from "node:assert/strict";
import test, { afterEach } from "node:test";
import { ApiError, req } from "./http.ts";

const original = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = original;
});
const respond = (body: string, status: number) => {
  globalThis.fetch = async () => new Response(body, { status });
};
async function failure(): Promise<ApiError> {
  try {
    await req("/api/runs/absent");
  } catch (error) {
    assert.ok(error instanceof ApiError);
    return error;
  }
  assert.fail("request unexpectedly succeeded");
}

test("HTTP failures retain status and raw body without classifying network errors as not-found", async () => {
  respond("missing", 404);
  const error = await failure();
  assert.equal(error.status, 404);
  assert.equal(error.message, "404 Not found.");
  assert.equal(error.body, "missing");
  globalThis.fetch = async () => {
    throw new Error("404-like network message");
  };
  await assert.rejects(
    req("/api/runs/absent"),
    (e) => !(e instanceof ApiError),
  );
});

test("error messages use the API's JSON detail when it is present", async () => {
  respond(
    JSON.stringify({ detail: "decision must be 'confirm' or 'override'" }),
    400,
  );
  assert.equal(
    (await failure()).message,
    "400 decision must be 'confirm' or 'override'",
  );
  respond(
    JSON.stringify({
      detail: [
        { loc: ["body", "reviewer"], msg: "Field required", type: "missing" },
        { loc: ["body", "reason"], msg: "Input should be a string" },
      ],
    }),
    422,
  );
  assert.equal(
    (await failure()).message,
    "422 Field required; Input should be a string",
  );
});

test("raw or unusable bodies are never displayed, only kept on the error", async () => {
  const page = "<html><body><h1>502 Bad Gateway</h1>nginx</body></html>";
  respond(page, 502);
  const proxy = await failure();
  assert.equal(proxy.message, "502 The API is unavailable.");
  assert.equal(proxy.body, page);
  for (const body of [
    "",
    "{}",
    '{"detail": {"nested": true}}',
    '{"detail": ""}',
  ]) {
    respond(body, 500);
    assert.equal((await failure()).message, "500 The API reported an error.");
  }
  respond("teapot", 418);
  assert.equal((await failure()).message, "418 The request failed.");
});

test("long details are truncated for display while the raw body is retained", async () => {
  const detail = "x".repeat(5000);
  respond(JSON.stringify({ detail }), 409);
  const error = await failure();
  assert.ok(error.message.length <= 240);
  assert.ok(error.message.startsWith("409 xxx"));
  assert.ok(error.message.endsWith("…"));
  assert.equal(error.body, JSON.stringify({ detail }));
});

test("JSON transport preserves successful response and mutation request", async () => {
  globalThis.fetch = async (path, init) => {
    assert.equal(path, "/api/runs/id/review");
    assert.equal(init?.method, "POST");
    assert.deepEqual(init?.headers, { "Content-Type": "application/json" });
    assert.equal(init?.body, '{"decision":"confirm"}');
    return Response.json({ saved: true });
  };
  assert.deepEqual(
    await req("/api/runs/id/review", {
      method: "POST",
      body: '{"decision":"confirm"}',
    }),
    { saved: true },
  );
});
