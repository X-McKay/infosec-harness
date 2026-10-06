import assert from "node:assert/strict";
import test from "node:test";
import type { components } from "../api/schema";
import {
  claimOrigin,
  evidenceBasis,
  finalProbeLine,
  originSummary,
  otherObservations,
  probeClaims,
  probeGaps,
  recordedValue,
  reportExcerpted,
  sourceVerified,
  workspaceDigest,
} from "./provenance.ts";

type Evidence = components["schemas"]["Evidence"];

const evidence = (overrides: Partial<Evidence> = {}): Evidence => ({
  id: "probe:3:call-1",
  kind: "probe",
  command: "python probe.py",
  exit_code: 0,
  stdout: "",
  stderr: "",
  timed_out: false,
  output_truncated: false,
  sandbox_id: "sandbox-1",
  source_digest: "sha256:source",
  observations: {},
  ...overrides,
});

// The finalized report shape: probe claims parsed by agents/evidence.py with
// origin "self_reported", receipt fields from workflows/investigation.py finalize(), and
// report_excerpted from contracts.Evidence.excerpt().
const complete = evidence({
  observations: {
    target_reached: true,
    oracle_valid: true,
    positive_control: true,
    negative_control: true,
    vulnerability_observed: false,
    origin: "self_reported",
    workspace_digest: "sha256:workspace",
    source_verified: true,
    report_excerpted: false,
  },
});

test("recorded claims are presented as recorded, including false", () => {
  assert.deepEqual(
    probeClaims(complete).map((row) => [row.key, row.value]),
    [
      ["target_reached", true],
      ["oracle_valid", true],
      ["positive_control", true],
      ["negative_control", true],
      ["vulnerability_observed", false],
    ],
  );
  assert.equal(claimOrigin(complete), "self_reported");
  assert.equal(sourceVerified(complete), true);
  assert.equal(workspaceDigest(complete), "sha256:workspace");
  assert.equal(reportExcerpted(complete), false);
  assert.deepEqual(otherObservations(complete), []);
});

test("missing or non-boolean claims are not recorded, never true", () => {
  const malformed = evidence({
    observations: { target_reached: "true", oracle_valid: 1, origin: "" },
  });
  assert.deepEqual(
    probeClaims(malformed).map((row) => row.value),
    [null, null, null, null, null],
  );
  assert.equal(claimOrigin(malformed), null);
  assert.equal(sourceVerified(malformed), null);
  assert.equal(recordedValue(null), "not recorded");
  assert.equal(recordedValue(false), "false");
  // Observations are optional in the schema.
  const absent = evidence({ observations: undefined });
  assert.equal(probeClaims(absent).length, 5);
  assert.equal(workspaceDigest(absent), null);
});

test("recorded values meeting complete_verified_probe have no gaps", () => {
  assert.deepEqual(probeGaps(complete), []);
});

test("each complete_verified_probe condition is reported when it fails", () => {
  const observations = complete.observations!;
  const cases: [Partial<Evidence>, string][] = [
    [{ kind: "command" }, "not a probe"],
    [{ exit_code: 137 }, "exit code 137"],
    [{ exit_code: null }, "no exit code recorded"],
    [{ timed_out: true }, "timed out"],
    [{ output_truncated: true }, "output truncated"],
    [
      { observations: { ...observations, workspace_digest: null } },
      "no workspace digest",
    ],
    [
      { observations: { ...observations, source_verified: false } },
      "not source-verified",
    ],
    [
      { observations: { ...observations, negative_control: false } },
      "negative control not true",
    ],
    [
      { observations: { ...observations, vulnerability_observed: "yes" } },
      "vulnerability observation not recorded",
    ],
  ];
  for (const [override, gap] of cases)
    assert.ok(
      probeGaps({ ...complete, ...override }).includes(gap),
      `${gap} expected`,
    );
  // A never-run probe (integrity refusal in tools/execute.py) reports every missing part.
  const refused = evidence({
    exit_code: null,
    observations: { source_verified: false, integrity_feedback: "refused" },
  });
  // exit code, digest, source verification, four prerequisites, the observation.
  assert.equal(probeGaps(refused).length, 8);
  assert.deepEqual(otherObservations(refused), [
    ["integrity_feedback", "refused"],
  ]);
});

test("the basis notice names every recorded origin and treats absence as not recorded", () => {
  assert.equal(evidenceBasis([]), null);
  assert.equal(evidenceBasis([evidence({ kind: "command" })]), null);
  const basis = evidenceBasis([
    complete,
    complete,
    evidence({ observations: {} }),
    evidence({ kind: "command", observations: { origin: "controller" } }),
  ])!;
  assert.equal(basis.probes, 3);
  assert.deepEqual(basis.origins, ["self_reported", null]);
  assert.equal(originSummary(basis), "self reported, not recorded");
});

test("only a prefixed final stdout line is the probe line", () => {
  const line = 'HARNESS_PROBE {"target_reached": true}';
  assert.equal(finalProbeLine(`building\n${line}\n`), line);
  assert.equal(finalProbeLine(`${line}\r\n\r\n`), line);
  assert.equal(finalProbeLine(`${line}\ntrailing`), null);
  assert.equal(finalProbeLine("HARNESS_PROBE"), null);
  assert.equal(finalProbeLine(""), null);
});

test("non-text observation values are listed as text", () => {
  assert.deepEqual(
    otherObservations(
      evidence({
        observations: { timeout_feedback: "Killed", attempts: 2, flag: null },
      }),
    ),
    [
      ["attempts", "2"],
      ["flag", "null"],
      ["timeout_feedback", "Killed"],
    ],
  );
});
