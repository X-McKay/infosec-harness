---
name: cwe-682-incorrect-calculation
description: Recognize incorrect calculations and precision loss and define a business-logic oracle with
  controls. Use this when the finding is CWE-682/1339 or a computed value is wrong for valid input.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-682: Incorrect calculation

Covers CWE-1339 (insufficient precision / accuracy of a stored value), including float rounding,
off-by-one, wrong operator/units, and lost precision.

## Use this skill when

- The finding is CWE-682 or 1339, or names an incorrect calculation, rounding error, precision
  loss, or off-by-one in a value used for a decision.
- A computed figure (price, total, fee, quota, allocation, balance, score) is wrong for in-range
  valid input, and the wrongness has a consequence.

## Do not use this skill when

- The value wraps or truncates at a type boundary — use `cwe-190-integer-overflow`.
- The wrong value is then used as a buffer size/index — the memory access skill wins for the sink.
- The calculation is right but the inputs are unvalidated — use `cwe-20-improper-input-validation`.

## When another skill also applies

- `cwe-190-integer-overflow`: a value crossing a type's range. **That skill wins** for wrap /
  truncation / sign change; **this skill wins** for a logic/precision error that stays within range
  (wrong formula, float rounding, off-by-one, wrong rounding direction).

## Procedure

**Sink.** The expression producing a value a decision depends on: a total/price/fee computation,
a proration, a float used where exact decimal is required (money), an off-by-one in a boundary
(`<=` vs `<`, inclusive/exclusive range), a unit mismatch, or an averaging/aggregation error.

**Guard.** Use of an exact type where required (`Decimal`, integer cents, `BigDecimal`), a correct
rounding mode applied once at the boundary, a formula matching the specification, or a post-condition
check (invariant, reconciliation) that rejects an inconsistent result.

**Neutralized when.** The calculation uses the correct types/precision and formula, or a
post-condition catches and rejects a wrong result before it has effect.

## Oracle

Condition: **for a chosen valid input the target returns a value that differs from the correct
value by a consequential amount** (crosses a threshold, loses/gains money, admits/denies wrongly).
This is a business-logic oracle: the "correct" value must be computed independently, not copied from
the code under test.

- Pick inputs that expose the error: amounts that trigger float rounding
  (`0.1 + 0.2`-style accumulation), boundary values for an off-by-one (exactly at the limit), or a
  case where the wrong operator/precision changes the outcome.
- Compute the expected value by an independent method (exact `Decimal`/integer arithmetic, or a hand
  calculation stated in the probe), and compare.
- Show the error has a *consequence*: the wrong value crosses a decision boundary (e.g. a free-ship
  threshold, a credit limit, a discount tier), not merely a sub-cent cosmetic difference — unless
  the finding's context makes the small difference material (accumulated over many operations,
  financial reconciliation).

Map onto `HARNESS_PROBE` (see `probe`):

- `target_reached`: the real calculation callable ran with the chosen valid input.
- `oracle_valid`: the comparison is against an independently computed expected value, and the
  consequence (threshold/decision) is defined.
- `positive_control`: a case with a known-correct expected value where the error is largest shows
  the discrepancy, proving the comparison discriminates.
- `negative_control`: an input where the buggy and correct formulas agree returns the matching
  value (the oracle stays silent), confirming it does not flag everything.
- `vulnerability_observed`: the real target returned a value differing consequentially from the
  independent expectation for valid input.

A target computing correctly is `target_reached: true, vulnerability_observed: false`.

## Language notes

- **Python:** binary `float` for money is the classic CWE-1339; the guard is `decimal.Decimal` or
  integer cents. `round()` uses banker's rounding — a mismatch with an expected half-up is a real
  finding.
- **Java:** `double`/`float` vs `BigDecimal`; integer division truncating (`a/b` on ints) is a
  frequent off-by.
- **JS:** all numbers are IEEE-754 doubles; large integers lose precision beyond 2^53 —
  `BigInt`/decimal libraries are the guards.
- State the specification the calculation must meet; without it, "wrong" is undefined.

## Pitfalls

- Deriving the "correct" value from the same code proves nothing — compute it independently.
- A sub-cent rounding difference is only a vulnerability if the context makes it material; do not
  overstate a cosmetic discrepancy.
- Ensure the error changes a *decision or stored value*, not just a display string, unless the
  finding is specifically about the stored precision.

## Verdict guidance

- `potentially_exploitable` needs a complete probe where the real target's value differed
  consequentially from an independent expectation on valid input, both controls green, with the
  affected decision named.
- `likely_not_exploitable` needs the exact-type / correct-formula / post-condition guard cited at
  its line and a probe showing the value matches the independent expectation.
- `inconclusive` when the correct value cannot be established independently or no consequence can be
  shown; say which.
