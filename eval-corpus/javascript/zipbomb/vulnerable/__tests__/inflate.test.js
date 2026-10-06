const test = require("node:test");
const assert = require("node:assert");
const zlib = require("zlib");
const { inflate } = require("../src/inflate");

// A small, bounded gzip payload that expands ~1000x. We measure the growth ratio
// on a bounded 4 MiB output; we never run to actual memory exhaustion.
const EXPANDED = 4 * 1024 * 1024;

test("small gzip expands with no size cap", () => {
  const payload = zlib.gzipSync(Buffer.alloc(EXPANDED));
  const out = inflate(payload);
  assert.strictEqual(out.length, EXPANDED);
  // Super-linear: output is orders of magnitude larger than the input.
  assert.ok(out.length / payload.length > 100);
});

test("ordinary small input round-trips", () => {
  const payload = zlib.gzipSync(Buffer.from("hello"));
  assert.strictEqual(inflate(payload).toString(), "hello");
});
