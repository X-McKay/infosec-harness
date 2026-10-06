---
name: cwe-400-uncontrolled-resource-consumption
description: Unbounded memory or CPU use, including decompression and expansion bombs. Use this when the finding is CWE-400/770/789/409/776.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-400: Uncontrolled resource consumption

Covers CWE-770 (allocation without limits), CWE-789 (memory allocation with an
attacker-controlled size), CWE-409 (decompression bombs), and CWE-776 (entity-expansion / XML
"billion laughs" bombs).

## Use this skill when

- The finding is CWE-400, 770, 789, 409 or 776, or names resource exhaustion, a zip/gzip bomb,
  an unbounded allocation, or entity expansion.
- An attacker-controlled count, size, depth, or compressed/encoded input drives allocation, loop
  iterations, recursion, or expansion with no cap.

## Do not use this skill when

- The cost comes from catastrophic regex backtracking — use `cwe-1333-regex-denial-of-service`.
- The loop never terminates (not just slow/large) — use `cwe-835-infinite-loop`.
- Resources are allocated but never released over time — use `cwe-401-missing-release-of-memory`.

## When another skill also applies

- `cwe-1333-regex-denial-of-service` and `cwe-835-infinite-loop` are the specific CPU cases. **They
  win** for backtracking and non-termination respectively; keep this skill for size/volume growth.
- `cwe-611-xxe`: an entity bomb is parsed by an XML parser. **This skill wins** when the hazard is
  expansion volume (CWE-776); `cwe-611-xxe` wins when the hazard is external-entity file/SSRF access.

## Procedure

**Sink.** Allocation or work sized by untrusted input with no ceiling: `malloc(n)` / `new T[n]` /
`bytes(n)` / list-multiply with attacker `n`; reading a whole decompressed stream into memory;
an XML/JSON parser expanding nested entities or deeply nested structures; an unbounded accumulator.

**Guard.** A hard cap checked before the work: a maximum length/count/depth, a streaming reader
with a byte ceiling, `max_entity_expansion` / DTD disabled, a quota, or back-pressure.

**Neutralized when.** Input size, output size, recursion depth, or expansion factor is bounded
before allocation, and the bound is small enough to be safe.

## Oracle

Condition: **a small bounded input causes super-linear (or grossly disproportionate) resource use.**
**Never run to exhaustion.** Measure *growth*, not absolute collapse: pick two or three small
input sizes well within the command budget and compare the resource used (peak memory, output
bytes, or allocation request) at each.

- Use small inputs: e.g. a decompression bomb represented by a few KB that expands to a measured
  (not realized-to-OOM) ratio; an entity-expansion document with depth 3 vs depth 5; an
  allocation driver asked for the *requested* size (read the argument) rather than actually
  allocating gigabytes.
- Prefer measuring the *requested*/declared size or a capped sample: read the size the code would
  allocate, or expand under a `resource.setrlimit`(AS)/ulimit cap and observe that the cap is hit,
  rather than letting the sandbox actually exhaust memory.
- Compute the growth ratio: output-or-memory divided by input. Linear-with-small-constant is safe;
  a ratio that climbs steeply with input size (quadratic/exponential, e.g. >100x and rising) is
  the finding.

Map onto `HARNESS_PROBE` (see `probe`):

- `target_reached`: the real callable ran with the finding-shaped input, including when its cap
  rejects it.
- `oracle_valid`: the measurement captured resource use at two+ sizes and the ratio is computed;
  the run stayed well inside the budget and did not attempt actual exhaustion.
- `positive_control`: a deliberately unbounded equivalent shows the steep growth, proving the
  measurement discriminates.
- `negative_control`: a benign bounded input shows flat/linear growth.
- `vulnerability_observed`: the finding-shaped input through the real target showed the
  super-linear growth (or the declared allocation exceeded any safe ceiling) with no cap applied.

A target whose cap holds is `target_reached: true, vulnerability_observed: false`.

## Language notes

- **Python:** cap probe memory with `resource.setrlimit(RLIMIT_AS, ...)`; read `zipfile`/`gzip`
  member `file_size` without decompressing, or decompress in bounded chunks and stop early.
- **JS/Node:** measure `process.memoryUsage().heapUsed` deltas; inspect declared sizes before
  buffering. Set a small `--max-old-space-size` to make a cap breach observable without a full OOM.
- **XML (CWE-776):** count expanded character length at small depths; secure parsers cap or
  disable entity expansion — cite the configuration.

## Pitfalls

- **Do not actually exhaust the sandbox.** A run killed at exit 137 proves a limitation, not the
  finding. The oracle must finish and *report a ratio*.
- Absolute timing/memory is noisy; the *ratio between sizes* is the signal, not a single number.
- Allocating the real huge buffer is both unsafe and unnecessary — read the requested size.
- A GC language may tolerate transient spikes; measure peak, not steady-state.

## Verdict guidance

- `potentially_exploitable` needs a complete probe reporting a steep growth ratio through the real
  target on small inputs, both controls green, and no cap in the path.
- `likely_not_exploitable` needs the size/depth cap cited at its line and a probe showing flat
  growth or the cap engaging.
- `inconclusive` when the sandbox cannot measure growth safely, or the input could not be reduced
  to a bounded sample; say which, and never substitute an exhaustion kill for a measurement.
