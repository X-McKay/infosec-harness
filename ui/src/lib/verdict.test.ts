import assert from "node:assert/strict";
import test from "node:test";
import {
  VERDICT_LABELS,
  isVerdictLabel,
  verdictLabel,
  verdictMeaning,
  verdictVariant,
} from "./verdict.ts";

// Verdict.label in contracts.py.
test("the three contract labels map to distinct badges", () => {
  assert.deepEqual([...VERDICT_LABELS].sort(), [
    "inconclusive",
    "likely_not_exploitable",
    "potentially_exploitable",
  ]);
  assert.equal(
    new Set(VERDICT_LABELS.map((label) => verdictVariant(label))).size,
    3,
  );
});

test("absent or unrecognized verdicts are never shown as a recorded outcome", () => {
  for (const value of [null, undefined, "", "exploitable", "complete"]) {
    assert.equal(verdictVariant(value), "outline");
    assert.equal(isVerdictLabel(value), false);
  }
  assert.equal(verdictLabel(null), "No verdict");
  assert.equal(verdictLabel(""), "No verdict");
  assert.equal(
    verdictLabel("potentially_exploitable"),
    "potentially exploitable",
  );
  assert.match(verdictMeaning(undefined), /No verdict/);
});

test("definitive meanings name the self-reported probe basis", () => {
  for (const label of ["potentially_exploitable", "likely_not_exploitable"])
    assert.match(verdictMeaning(label), /self-reported/);
  assert.match(verdictMeaning("inconclusive"), /limitations/);
});
