import assert from "node:assert/strict";
import test from "node:test";
import { executionProvenance, originSummary } from "./provenance.ts";

const controllerRecord = {
  process: { origin: "controller" },
  observations: { origin: "controller" },
  runner: { origin: "controller" },
};

test("no executions means no evidence-basis notice", () => {
  assert.equal(executionProvenance([]), null);
});

// Persisted ProbeExecution records currently carry no origin sections.
test("executions without recorded origins are never presented as verified", () => {
  const provenance = executionProvenance([
    { attempt: 1, exit_code: 0, oracle_fired: true },
  ]);
  assert.equal(provenance?.verified, false);
  assert.deepEqual(provenance?.origins, {
    observations: [null],
    process: [null],
    runner: [null],
  });
  assert.equal(
    originSummary(provenance!),
    "observations: not recorded · process: not recorded · runner: not recorded",
  );
});

// Shape written by sandbox/evidence.py execution_record.
test("self-reported markers and parsed runner output keep the warning", () => {
  const provenance = executionProvenance([
    {
      process: { origin: "controller" },
      observations: { origin: "self_reported_marker" },
      runner: { origin: "parsed_untrusted_output" },
    },
  ]);
  assert.equal(provenance?.verified, false);
  assert.equal(
    originSummary(provenance!),
    "observations: self reported marker · process: controller · runner: parsed untrusted output",
  );
});

test("verification requires every origin of every execution to be controller-authored", () => {
  assert.equal(executionProvenance([controllerRecord])?.verified, true);
  for (const weaker of [
    { ...controllerRecord, runner: { origin: "not_available" } },
    { ...controllerRecord, runner: undefined },
    { ...controllerRecord, observations: { origin: "Controller" } },
    { ...controllerRecord, process: { origin: 1 } },
    { ...controllerRecord, process: ["controller"] },
    null,
    "controller",
  ])
    assert.equal(
      executionProvenance([controllerRecord, weaker])?.verified,
      false,
    );
});
