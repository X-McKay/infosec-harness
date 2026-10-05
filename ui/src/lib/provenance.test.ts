import assert from "node:assert/strict";
import test from "node:test";
import type { RunDetail } from "../api/client.ts";
import { executionProvenance, originSummary } from "./provenance.ts";

type Execution = NonNullable<RunDetail["evidence"]>["executions"][number];

const execution = (origins: Execution["origins"]): Execution => ({
  attempt: 1,
  exit_code: 0,
  timed_out: false,
  oracle_fired: true,
  precondition_reached: true,
  sink_returned: true,
  runner_reported_no_tests: null,
  stdout_tail: "",
  stderr_tail: "",
  duration_s: 1,
  log_artifact: null,
  source_artifact: null,
  origins,
});

// The persisted shape: ProbeExecution.origins, from sandbox/evidence.py execution_record.
const persisted = execution({
  process: {
    exit_code: 0,
    timed_out: false,
    duration_s: 1,
    origin: "controller",
  },
  observations: {
    precondition_reached: true,
    sink_returned: true,
    oracle_fired: true,
    origin: "self_reported_marker",
  },
  runner: { zero_test_signal: null, origin: "parsed_untrusted_output" },
});

const controllerOnly = {
  origins: {
    process: { origin: "controller" },
    observations: { origin: "controller" },
    runner: { origin: "controller" },
  },
};

test("no executions means no evidence-basis notice", () => {
  assert.equal(executionProvenance([]), null);
});

test("a probe that never ran records no origins and is never verified", () => {
  const provenance = executionProvenance([execution(null)]);
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

test("persisted self-reported markers and parsed runner output keep the warning", () => {
  const provenance = executionProvenance([persisted]);
  assert.equal(provenance?.verified, false);
  assert.equal(
    originSummary(provenance!),
    "observations: self reported marker · process: controller · runner: parsed untrusted output",
  );
});

test("origins are read only from the persisted origins section", () => {
  // Section-shaped fields at the top level of an execution are not its recorded origins.
  const misplaced = {
    process: { origin: "controller" },
    observations: { origin: "controller" },
    runner: { origin: "controller" },
  };
  assert.equal(executionProvenance([misplaced])?.verified, false);
});

test("verification requires every origin of every execution to be controller-authored", () => {
  assert.equal(executionProvenance([controllerOnly])?.verified, true);
  const sections = controllerOnly.origins;
  for (const weaker of [
    { origins: { ...sections, runner: { origin: "not_available" } } },
    { origins: { ...sections, runner: undefined } },
    { origins: { ...sections, observations: { origin: "Controller" } } },
    { origins: { ...sections, process: { origin: 1 } } },
    { origins: { ...sections, process: ["controller"] } },
    { origins: null },
    persisted,
    null,
    "controller",
  ])
    assert.equal(
      executionProvenance([controllerOnly, weaker])?.verified,
      false,
    );
});
