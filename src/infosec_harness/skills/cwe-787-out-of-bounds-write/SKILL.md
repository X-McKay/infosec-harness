---
name: cwe-787-out-of-bounds-write
description: C/C++ writes past a buffer boundary. Use this when the finding is CWE-787/119/120/121/122/124.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-787: Out-of-bounds write

Covers the buffer-write family: CWE-119 (improper bounds), CWE-120 (classic overflow / missing
length check), CWE-121 (stack overflow), CWE-122 (heap overflow), CWE-124 (buffer underwrite).

## Use this skill when

- The finding is CWE-787, 119, 120, 121, 122 or 124, or names a buffer/stack/heap overflow.
- Untrusted length or data reaches `memcpy`, `strcpy`, `sprintf`, `gets`, a `[]` store, or a
  pointer write whose index or size is attacker-influenced.

## Do not use this skill when

- The code only *reads* past the end — use `cwe-125-out-of-bounds-read`.
- The buffer is freed before the write — use `cwe-416-use-after-free`.
- The hazard is an index/size *computation* that wraps before any access — use
  `cwe-190-integer-overflow`; return here once the wrapped value reaches the write.

## When another skill also applies

- `cwe-190-integer-overflow` also fires when a wrapped size or negative index produces the write.
  **This skill wins** once the out-of-bounds store is the observable consequence: the oracle
  watches the write, and the overflow is the source feeding it. Cite both CWEs; probe the write.
- `cwe-125-out-of-bounds-read` also fires when the same loop reads and writes out of bounds.
  **This skill wins** when a write corrupts memory; an OOB write is the higher-severity sink.

## Procedure

**Sink.** A store that can land outside the destination object: `memcpy`/`memmove`/`strcpy`/
`strcat`/`sprintf`/`gets`/`scanf("%s")`, or `buf[i] = v` / `*p = v` where `i`, the length, or
`p` is derived from untrusted input without a bound check against the real capacity.

**Guard.** A length or index comparison against the destination's true size that executes on
the input path, using the destination capacity (not the source length), with the correct
relation (`<` vs `<=`, room for a NUL terminator).

**Neutralized when.** The copy is bounded by the destination size (`snprintf`, `strlcpy`,
`memcpy(dst, src, min(n, cap))`), the index is range-checked against capacity, or a
bounds-safe type (`std::string`, `std::vector::at`) replaces the raw buffer.

## Oracle

Condition: **a store landed outside the destination object.** Use a small bounded input that
is just large enough to cross the boundary (for example capacity+8 bytes), never a megabyte
flood — the point is to observe the one byte past the end, not to exhaust anything.

Pick the strongest oracle the sandbox supports; establish which at run time, do not assume:

- **ASan (preferred when available).** Compile the target with `gcc -fsanitize=address -g`.
  First confirm ASan works: compile and run a tiny instrumented program that writes
  `a[n]` one past a stack array and check for an `ERROR: AddressSanitizer` line and non-zero
  exit. If that confirmation fails, fall back below.
- **Guard bytes / canary (no ASan).** Place the target buffer inside a struct between two
  known sentinel fields (or a `malloc`'d region flanked by sentinel pages of known bytes).
  After the target call, check whether a sentinel changed.
- **Controlled crash.** If neither is reliable, a write far enough past the end to hit an
  unmapped page makes the process die with SIGSEGV (exit 139) or `*** stack smashing detected ***`
  / SIGABRT (exit 134) when `-fstack-protector` is on. Treat the signal as the observable.

Map onto `HARNESS_PROBE` (see `probe`):

- `target_reached`: the real function compiled and ran with the finding-shaped input,
  including when its own bound check rejects the input and returns normally.
- `oracle_valid`: the chosen detector (ASan / sentinel / signal) is in place and inspected.
- `positive_control`: a deliberately oversized write through the *same* detector fires it
  (ASan report, sentinel changed, or crash), proving the detector works.
- `negative_control`: an in-bounds input runs the target with no report, no sentinel change
  and a clean exit.
- `vulnerability_observed`: the finding-shaped input through the real target fired the detector.

`target_reached` means the real target ran with the input, not that it overflowed; a target
that bounds the copy is `target_reached: true, vulnerability_observed: false`.

## Language notes

- **C/C++:** `gcc` and `make` are in the workspace; the ASan runtime ships with the compiler.
  Compilation needs C headers — if `stdio.h` is missing, report the toolchain limitation rather
  than inventing a result. Prefer `-g -O0` so line numbers in a report map to the sink.
- Managed languages (Python/Java/JS) do not have this class at the language level; a report
  there usually points at a native extension or an unsafe API — scope to that boundary.

## Pitfalls

- A huge input flood can crash for reasons unrelated to the finding (allocation failure); use
  the smallest input that crosses the boundary so the signal is attributable.
- Stack-protector catches some stack overflows but not heap ones; absence of a crash with
  stack-protector on is not proof of safety — prefer ASan or sentinels.
- `-O2` can optimize a sentinel check away; keep the detector in `volatile` storage or use ASan.
- Never derive `vulnerability_observed` from the positive control; it tests the detector only.

## Verdict guidance

- `potentially_exploitable` needs a complete probe where the finding-shaped bounded input fired
  the detector through the real target, with both controls green.
- `likely_not_exploitable` needs the bound check cited at its source line and a probe showing the
  input is confined (`target_reached: true, vulnerability_observed: false`).
- `inconclusive` when the toolchain cannot compile the target or no detector can be established;
  say which, and that a configured bound is not execution evidence.
