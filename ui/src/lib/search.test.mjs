import assert from "node:assert/strict";
import test from "node:test";
import { parseFindingSearch } from "./search.ts";

test("route state retains supported drill-down filters", () => {
  assert.deepEqual(
    parseFindingSearch({
      population: "demo",
      metric: "cost_usd",
      lower: "1.25",
      upper: "2.5",
      upper_inclusive: "true",
      offset: "25",
    }),
    {
      verdict: "",
      batch_id: "",
      search: "",
      offset: 25,
      population: "demo",
      metric: "cost_usd",
      lower: 1.25,
      upper: 2.5,
      upper_inclusive: true,
    },
  );
});

test("route state discards unsupported API enum values", () => {
  const parsed = parseFindingSearch({
    population: "all",
    metric: "accuracy",
  });
  assert.equal(parsed.population, undefined);
  assert.equal(parsed.metric, undefined);
});
