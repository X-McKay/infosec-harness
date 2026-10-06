import assert from "node:assert/strict";
import test from "node:test";
import { nextRowIndex, typingTarget } from "./keyboard.ts";

test("j and k enter the list and move within it, clamped at the ends", () => {
  assert.equal(nextRowIndex("j", -1, 5), 0);
  assert.equal(nextRowIndex("k", -1, 5), 4);
  assert.equal(nextRowIndex("j", 2, 5), 3);
  assert.equal(nextRowIndex("j", 4, 5), 4);
  assert.equal(nextRowIndex("k", 0, 5), 0);
});

test("arrow, Home and End keys move only once a row has focus", () => {
  assert.equal(nextRowIndex("ArrowDown", -1, 5), null);
  assert.equal(nextRowIndex("ArrowUp", -1, 5), null);
  assert.equal(nextRowIndex("Home", -1, 5), null);
  assert.equal(nextRowIndex("ArrowDown", 1, 5), 2);
  assert.equal(nextRowIndex("ArrowUp", 1, 5), 0);
  assert.equal(nextRowIndex("Home", 3, 5), 0);
  assert.equal(nextRowIndex("End", 0, 5), 4);
});

test("other keys and empty lists never move", () => {
  assert.equal(nextRowIndex("x", 0, 5), null);
  assert.equal(nextRowIndex("Enter", 0, 5), null);
  assert.equal(nextRowIndex("j", -1, 0), null);
});

test("shortcuts stay out of fields and modified keys", () => {
  const plain = { metaKey: false, ctrlKey: false, altKey: false };
  const inField = { closest: (selector: string) => selector.includes("input") };
  const outside = { closest: () => null };
  assert.equal(typingTarget(plain, inField), true);
  assert.equal(typingTarget(plain, outside), false);
  assert.equal(typingTarget(plain, null), false);
  assert.equal(typingTarget({ ...plain, metaKey: true }, outside), true);
  assert.equal(typingTarget({ ...plain, ctrlKey: true }, outside), true);
});
