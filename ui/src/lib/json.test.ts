import assert from "node:assert/strict";
import test from "node:test";
import { asRecord, isRecord, numeric, text } from "./json.ts";

test("recorded JSON narrowing accepts finite measurements without coercing absent data", () => {
  for (const invalid of [null, undefined, "1", NaN, Infinity, -Infinity])
    assert.equal(numeric(invalid), null);
  assert.equal(numeric(0), 0);
  assert.equal(text(""), null);
  assert.equal(text(1), null);
  assert.equal(text("complete"), "complete");
  assert.equal(isRecord([1]), false);
  assert.equal(isRecord(null), false);
  assert.deepEqual(asRecord([1]), {});
  assert.deepEqual(asRecord(null), {});
  assert.deepEqual(asRecord({ n: 0 }), { n: 0 });
});
