---
name: probe
description: Load before writing or running any probe. Author and run a focused offline probe with controls that ends in the HARNESS_PROBE observation line.
---

Trace the finding's real attacker-controlled value to the sensitive operation; the matching
`cwe-*` skill defines the oracle and controls. Inspect the actual function signature and
preconditions.

## Real target, real inputs

- A probe must execute the target code as built for its real runtime. Reimplementing the
  target in another language, replacing its runtime or standard library with stubs, mocking
  the sink, or simulating the environment is a stand-in: it may explain intent but does not
  establish behaviour, must not carry a definitive label, and the verdict must be
  `inconclusive` with the limitation named (the precedent is `cwe-918-ssrf`'s rule on
  patched resolvers).
- A probe varies only inputs the sink actually receives from a caller (arguments, request
  fields, files the application reads by design). It must not change the interpreter's
  module search path, environment variables, working directory, installed packages or files
  the application does not take from the caller; a probe that does so is disqualified and
  must not be cited, and a later probe may not supersede an earlier one on that basis.
- The untrusted input is what the finding names as attacker-controlled. Other parameters
  (buffer sizes, configuration, handles, callbacks) belong to the trusted caller's contract;
  a probe that varies them demonstrates caller misuse, not the reported vulnerability, unless
  the finding or the code shows they come from the caller's untrusted data.

## Prepare and run

- `run_probe` copies only `/workspace/repo` into a fresh offline sandbox and starts there.
  Use `write` for probe files and `execute` for setup, all under `/workspace/repo`; anything
  prepared in `/tmp` or a home directory does not transfer. Fixtures and marker files the
  probe itself creates at run time (for example with `tempfile.mkdtemp()`) are fine.
- Never modify original source files. They are checked against the immutable snapshot after
  the run; a change invalidates it. Do not patch the target to manufacture a conclusion.
- The archive check rejects symlinks, hardlinks and special files. Remove only those the probe
  created, in a `finally` block before exit; use `os.path.lexists` for dangling links. A run
  that returns `integrity_feedback` completed but is not source-verified.
- Make the runner really run the probe: exit 0 with zero tests is not success. Pytest captures
  stdout (use `-s`); Jest/Vitest may silence console output; Gradle may skip an up-to-date
  task; Maven may pick the wrong JUnit provider. Inspect runner output. Keep output short.
- Each tool call resends the whole conversation, so calls spend the budget: run variants as
  one list in one script, one output line each; edit and rerun one debug script instead of
  writing numbered copies; print the raw value (`repr`, `Data::Dumper`) once before guessing.

## Observation line

The last stdout line must hold the prefix and the JSON object on the SAME line, with exactly
these five boolean fields and nothing else; print details on earlier lines:

```text
HARNESS_PROBE {"target_reached":true,"oracle_valid":true,"positive_control":true,"negative_control":true,"vulnerability_observed":false}
```

The five values must be JSON booleans `true`/`false`; numbers, strings, extra fields, key=value
pairs or the prefix on its own line count as no observation. Emit the line with a JSON encoder:

- Python: `print('HARNESS_PROBE ' + json.dumps(observations))`
- Perl: `use JSON::PP; print 'HARNESS_PROBE ', JSON::PP->new->canonical->encode({ target_reached => $t ? JSON::PP::true : JSON::PP::false, ... }), "\n";` (plain `1`/`0` encode as numbers and are rejected)
- JavaScript: `console.log('HARNESS_PROBE ' + JSON.stringify(observations))` with boolean values
- Java: build the string by hand with the literal words `true`/`false`

- `target_reached`: the finding-shaped input invoked the real target entry point, including its
  validation or containment checks. A security rejection by the real target is still `true`
  (a real file reader refusing `../` while a normal read succeeds has reached the target).
  It does not mean the sink ran or the attack succeeded. Import or setup errors, missing
  dependencies, or a stand-in rejecting the input are `false`.
- `oracle_valid`: the oracle check executed and tests the condition the CWE skill names.
- `positive_control`: a deliberately triggered case made the oracle fire.
- `negative_control`: a benign or inert input left the oracle silent.
- `vulnerability_observed`: the oracle fired for the finding-shaped input through the real
  target. `false` is meaningful only when the other four are `true`.

Never report a control you did not execute. Values are self-reported claims, not proof.

## When the positive control fails

A `positive_control: false` means the oracle itself is broken, not that the target is safe:
your deliberately-triggered case did not make the oracle fire, so the check cannot tell
`vulnerability_observed: false` from a missed detection. **Stop after two attempts** and
re-examine the oracle: confirm the marker/nonce you write is the exact string you search for
(a fixed literal written but a random nonce searched is the classic bug), that the positive
control is the simplest entity-resolving parser rather than one with hand-toggled flags, and
that the target entry point and input shape match the real signature. If two attempts leave
the positive control `false`, record `inconclusive` and state the oracle limitation rather
than continuing. The same applies when the target run cannot be reached at all.

## Use the result

- A complete probe exits 0 with untruncated output, is source-verified, and reports the four
  prerequisite fields `true`. Only a cited complete probe whose `vulnerability_observed`
  matches the label supports a definitive verdict, and any complete probe contradicting it
  blocks that verdict. Failed, incomplete or unverified probes support only `inconclusive`;
  workspace `execute` runs and earlier exploratory probes cannot substitute.
- Derive `vulnerability_observed` only from the real target call with the finding-shaped
  input (for example a trace of the statements the target actually executed). Never derive
  it from the positive control: that reports the oracle, not the target.
- To correct a flawed complete probe, fix it, run a new `run_probe`, cite the new id, and list
  the flawed probe's id in the verdict's `superseded_evidence_ids`, explaining the flaw in the
  summary. Only probes older than the cited one can be superseded. Never relabel or
  reinterpret an old receipt; nothing is retried for you.
- Cite the exact full returned Evidence.id, including its tool-call suffix, plus the source
  lines the probe exercises.
- A hostile probe can mutate and restore files; do not claim independent attestation of
  untrusted test code.
