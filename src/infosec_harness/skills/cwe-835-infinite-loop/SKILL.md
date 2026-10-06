---
name: cwe-835-infinite-loop
description: Loops that may never terminate on some input. Use this when the finding is CWE-835.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-835: Loop with unreachable exit condition (infinite loop)

## Use this skill when

- The finding is CWE-835, or names an infinite loop or a loop that never terminates.
- A loop's exit depends on untrusted input and some input never satisfies it: a counter that can
  stop changing, a `while` on a condition the body may never falsify, a parser that fails to
  advance, a recursion without a shrinking argument.

## Do not use this skill when

- The loop terminates but is slow/expensive — use `cwe-400-uncontrolled-resource-consumption` or
  `cwe-1333-regex-denial-of-service`.
- The non-advance is caused by freed/null state corruption — use the matching memory skill.

## When another skill also applies

- `cwe-400-uncontrolled-resource-consumption`: a very long but *finite* loop is a resource issue.
  **This skill wins** only when the loop provably has no reachable exit for the input class; if it
  would terminate given time, treat it as CWE-400 and measure growth instead.

## Procedure

**Sink.** A loop or recursion whose termination condition can fail to be reached: `while (c)` where
the body may not change `c`; `for` with an index that can stop incrementing (e.g. an `i += step`
with `step == 0`); a read loop that does not advance on a zero-length/EOF-less input; mutual
recursion with no base case for some input.

**Guard.** A monotonic progress variable that always moves toward the exit, an iteration cap /
deadline inside the loop, or an invariant that guarantees the condition is eventually met.

**Neutralized when.** Every iteration makes measurable progress toward the exit, or a maximum
iteration count / timeout bounds the loop regardless of input.

## Oracle

Condition: **with a loop-controlling input the target does not terminate within N seconds, while a
control input terminates quickly.** Non-termination is only semi-decidable, so the oracle is a
deadline comparison, not a proof.

- Run the real callable with the finding-shaped input in a child process/thread under a strict
  in-probe deadline `N` (a few seconds) that is **well below the command budget** — so a hang is
  observed as "still running at N", not as the budget kill (exit 137).
- Run the same callable with a control input that is known to terminate; it must finish fast.
- Optionally instrument the loop variable (log iteration count) to show it stops advancing; this
  strengthens "does not terminate" beyond mere slowness.

Map onto `HARNESS_PROBE` (see `probe`):

- `target_reached`: the real callable started executing with the finding-shaped input.
- `oracle_valid`: a deadline `N` far below the budget was enforced in-probe and both the hanging
  and the terminating runs were observed under it.
- `positive_control`: a deliberately non-terminating equivalent is still running at `N`
  (deadline fires), proving the detector distinguishes a hang.
- `negative_control`: a benign input terminates well under `N`.
- `vulnerability_observed`: the finding-shaped input left the real target still running at `N`
  (and, where instrumented, the progress variable had stopped advancing).

A target that always makes progress (terminates under `N` for the crafted input too) is
`target_reached: true, vulnerability_observed: false`.

## Language notes

- **Python/JS/Java:** run the target in a `multiprocessing.Process` / worker thread / separate
  process and `join(N)`; if still alive, terminate it and record the hang. Do not use the
  command budget as the deadline.
- **C:** run the compiled target under `timeout N` inside the probe and treat exit 124/137 from
  *that inner* `timeout` (not the harness budget) as the hang signal; keep `N` small.
- Prefer a loop-controlling input that is minimal (the specific value that stops progress), so the
  hang is attributable to the finding and not to sheer input size.

## Pitfalls

- Slow is not infinite. If a larger input would eventually finish, this is CWE-400; show that the
  progress variable has genuinely stopped, not merely slowed.
- Letting the loop run to the command budget conflates a hang with any other long run; always use a
  smaller in-probe deadline so the observation is "running at N", recorded deliberately.
- A loop that catches an exception and `continue`s without advancing is a common real cause; check
  the body actually mutates the exit variable.

## Verdict guidance

- `potentially_exploitable` needs a complete probe where the crafted input was still running at a
  deadline below the budget through the real target, both controls green, ideally with a stalled
  progress variable.
- `likely_not_exploitable` needs the progress/iteration guard cited at its line and a probe showing
  termination for the crafted input.
- `inconclusive` when slowness cannot be distinguished from non-termination within a safe deadline;
  say so rather than guessing.
