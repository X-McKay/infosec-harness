const test = require("node:test");
const assert = require("node:assert");
const zlib = require("zlib");
const { inflate } = require("../src/inflate");

// A bounded 4 MiB expansion; no run reaches actual memory exhaustion.
const EXPANDED = 4 * 1024 * 1024;

test("4 MiB gzip expansion", () => {
  const payload = zlib.gzipSync(Buffer.alloc(EXPANDED));
  assert.throws(() => inflate(payload));
});

test("small input round-trips", () => {
  const payload = zlib.gzipSync(Buffer.from("hello"));
  assert.strictEqual(inflate(payload).toString(), "hello");
});
