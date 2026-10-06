---
name: cwe-190-integer-overflow
description: Integer overflow, truncation, conversion errors, unchecked indices and divide-by-zero. Use this when the finding is CWE-190/191/680/681/129/369.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-190: Integer overflow and related numeric errors

Covers CWE-191 (underflow / wraparound below zero), CWE-680 (overflow leading to buffer
overflow), CWE-681 (incorrect numeric-type conversion / truncation / sign change), CWE-129
(improper validation of an array index), and CWE-369 (divide by zero).

## Use this skill when

- The finding is CWE-190, 191, 680, 681, 129 or 369, or names integer overflow, wraparound,
  truncation, a signed/unsigned confusion, an unchecked index, or a divide-by-zero.
- Untrusted input participates in arithmetic (`a + b`, `n * size`, `len - k`), a narrowing cast
  (`(int)`, `(size_t)`, `int(x)` over a range), an array index, or a divisor.

## Do not use this skill when

- The out-of-bounds access itself is the finding and the arithmetic is incidental — use
  `cwe-787-out-of-bounds-write`/`cwe-125-out-of-bounds-read` (but cite 190 as the source).
- The result is a wrong business figure with no overflow/truncation — use
  `cwe-682-incorrect-calculation`.

## When another skill also applies

- `cwe-787-out-of-bounds-write` / `cwe-125-out-of-bounds-read`: the overflow often *feeds* an OOB
  access (CWE-680). **The access skill wins** when the memory violation is the observable sink;
  **this skill wins** when the wrap/truncation itself is observable (wrong size, wrong index,
  wrong branch) or the target is a managed language where the numeric error is the whole bug.
- `cwe-682-incorrect-calculation`: use that for precision/logic errors with no wrap; use this when
  a value crosses a type boundary.

## Procedure

**Sink.** Arithmetic or a conversion whose result is then trusted: a size/length passed to an
allocator or copy, an index into a buffer, a loop bound, a divisor, or a value narrowed to a
smaller type. In C/C++ unsigned wrap is defined (and dangerous); signed overflow is UB.

**Guard.** A range or overflow check on the operands *before* the operation, in the right order:
`if (n > MAX/size) fail;` before `n*size`; `if (b > a) fail;` before `a-b` on unsigned;
`if (i < 0 || i >= len) fail;` before indexing; `if (d == 0) fail;` before dividing; a widening
cast or a checked-arithmetic helper (`__builtin_mul_overflow`, `Math.addExact`).

**Neutralized when.** The check precedes the operation and uses the correct bound and signedness,
or a wide-enough type or checked-arithmetic API makes the wrap impossible.

## Oracle

Condition: **the operation produced a value outside its true mathematical range and that value
was then used.** Use small, specific boundary inputs — `SIZE_MAX`, `INT_MAX`, `INT_MIN`, `0`,
`-1`, `len`, `len+1` — never a loop that counts up to overflow. Observe the *consequence*:

- **Size/length (CWE-680):** the wrapped size yields a short allocation; pair with `cwe-787-out-of-bounds-write` for
  the write, or observe the allocation size directly (requested N vs actual capacity).
- **Index (CWE-129):** a negative or wrapped index reaches an access; observe whether the access
  is in bounds.
- **Truncation / sign (CWE-681):** the narrowed value differs from the original; observe the two
  side by side (`print(original, narrowed)`), and that the narrowed one drives the decision.
- **Divide by zero (CWE-369):** a zero/`-1` divisor; observe SIGFPE (exit 136) in C or the
  language's `ZeroDivisionError`/`ArithmeticException` at the sink line.

Map onto `HARNESS_PROBE` (see `probe`):

- `target_reached`: the real function ran with the boundary input, including when its range check
  rejects it.
- `oracle_valid`: the check compares the computed value against its correct mathematical value (or
  the access bound / the fault), not merely that the function returned.
- `positive_control`: the unchecked operation computed directly on the same operands shows the
  wrap/truncation/fault.
- `negative_control`: an in-range input produces the correct value and no fault.
- `vulnerability_observed`: the boundary input through the real target produced the out-of-range
  value (or fault) and it was used downstream.

A target that range-checks first is `target_reached: true, vulnerability_observed: false`.

## Language notes

- **C/C++:** signed overflow is UB — compile with `-fsanitize=undefined` to catch it precisely
  (confirm UBSan works with a tiny probe); unsigned wrap is silent, so compare the computed size
  against the mathematical product. `gcc`/`make` are present; report a toolchain gap rather than
  guessing if headers are missing.
- **Python:** ints are arbitrary-precision, so classic overflow rarely applies — the real finding
  is usually a bad index, a `ZeroDivisionError`, or a `struct`/`ctypes`/`numpy` fixed-width cast.
  Scope accordingly.
- **Java/JS:** `int`/`long` and IEEE-754 `number` wrap/lose precision; `Math.*Exact` and `BigInt`
  are the guards.

## Pitfalls

- Testing with `INT_MAX` in Python proves nothing — match the input type to where the width lives.
- A wrap with no downstream use is not exploitable; show the value is trusted by a size, index,
  branch or divisor afterwards.
- Do not conflate the positive control (direct computation) with the target's behavior.

## Verdict guidance

- `potentially_exploitable` needs a complete probe where the boundary input produced and used an
  out-of-range value through the real target, both controls green, and a stated consequence.
- `likely_not_exploitable` needs the overflow/range/divisor check cited at its line and a probe
  showing the input is confined.
- `inconclusive` when the width or toolchain cannot be exercised deterministically; name the gap.
