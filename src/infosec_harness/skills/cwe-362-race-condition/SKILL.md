---
name: cwe-362-race-condition
description: Recognize race conditions and TOCTOU and define an interleaving oracle that stays
  inconclusive when it cannot force the race. Use this when the finding is CWE-362/367/366/364.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-362: Concurrent execution using shared resource (race condition)

Covers CWE-367 (TOCTOU: time-of-check to time-of-use), CWE-366 (race within a thread),
and CWE-364 (signal-handler race).

## Use this skill when

- The finding is CWE-362, 367, 366 or 364, or names a race condition, TOCTOU, or a check/use gap.
- A check and the action it guards are separated so another thread, process, or signal can change
  the shared state (file, variable, balance, flag) in between.

## Do not use this skill when

- The defect is single-threaded ordering (free-then-use with no concurrency) — use
  `cwe-416-use-after-free`.
- There is no shared mutable resource and no second actor — it is likely a different class.

## When another skill also applies

- `cwe-416-use-after-free`: a freed-then-used object across threads. **This skill wins** when the
  bug requires interleaving; `cwe-416` wins for a single-threaded ordering defect.
- `cwe-22-path-traversal` / file sinks: a TOCTOU often targets a file. **This skill wins** when the
  hazard is the check/use *window*; the sink skill defines what the window lets through.

## Procedure

**Sink.** A check-then-act on shared state with no atomicity: `if os.path.exists(p): open(p)`;
`if (!exists) create(p)`; read-modify-write of a counter/balance without a lock; a signal handler
touching state the main flow also touches; a "check permission then use handle" gap.

**Guard.** Atomic operations that fuse check and act: `os.open(..., O_CREAT|O_EXCL)`,
`O_NOFOLLOW`, file locks, a mutex/transaction around the read-modify-write, compare-and-swap, or
operating on a stable handle/fd rather than re-resolving a name.

**Neutralized when.** The check and action are atomic (single syscall, lock held across both, or
CAS), or the resource cannot be swapped by another actor in the window.

## Oracle

Condition: **interleaving the check and the use changes the outcome in a way the atomic version
prevents.** Races are inherently non-deterministic; prefer a *forced* interleaving over luck.

- **Deterministic hook (preferred).** Insert a synchronization point the test controls between the
  check and the use — monkeypatch the checked predicate to flip the shared state on first call, use
  a barrier/event, or a debugger-style hook — so the race is reproduced on demand. This gives a
  clean positive/negative.
- **Bounded stress (fallback).** Run many *short, fixed-cap* iterations (e.g. a few hundred) of two
  threads/processes contending, counting how often the invariant breaks. Keep the cap small and
  well inside the budget. A single break is enough to show the race; zero breaks after the cap is
  **not** proof of safety.
- Compare against the atomic/fixed version under the same harness, which must never break.

Map onto `HARNESS_PROBE` (see `probe`):

- `target_reached`: the real check-then-act callable ran under the interleaving harness.
- `oracle_valid`: the harness actually exercised the window (the hook fired, or the contended
  iterations ran under the fixed cap) and the invariant is checked.
- `positive_control`: a deliberately racy equivalent breaks the invariant under the same harness.
- `negative_control`: the atomic/fixed version never breaks the invariant under the same harness.
- `vulnerability_observed`: the real target's invariant broke under the forced/stressed interleaving.

If the harness cannot force or observe the interleaving (the hook could not be placed, or the
stress cap elapsed with no break and no deterministic hook), report `oracle_valid: false` or
`vulnerability_observed: false` honestly and treat the verdict as **inconclusive** — a race not
reproduced is not a race disproved.

## Language notes

- **Python:** the GIL serializes bytecode but not I/O or C calls; TOCTOU on files is real. Use
  `monkeypatch`/`unittest.mock` to flip state between `exists` and `open`, or `threading.Barrier`
  for counters. `os.open(..., O_CREAT|O_EXCL|O_NOFOLLOW)` is the file guard.
- **Java:** `synchronized`/`java.util.concurrent` locks and atomics are the guards; a hook can use a
  `CountDownLatch` to align threads.
- **JS:** single-threaded, but `await` points interleave; the race is between resumptions, forced by
  controlling promise resolution order.
- **Signals (CWE-364):** a handler touching non-atomic state; model by invoking the handler at the
  vulnerable point rather than relying on real signal timing.

## Pitfalls

- Non-reproduction is the default failure mode here; stay `inconclusive` rather than claiming
  `likely_not_exploitable` from a stress run that simply did not hit the window.
- Keep the stress cap fixed and small; an unbounded retry loop to "finally catch it" risks the
  budget kill and still proves nothing. Prefer the deterministic hook.
- Ensure the invariant check itself is race-free, or it becomes a second race and muddies results.

## Verdict guidance

- `potentially_exploitable` needs a complete probe where a forced or stressed interleaving broke the
  real target's invariant, both controls green.
- `likely_not_exploitable` needs the atomic guard (O_EXCL/lock/CAS) cited at its line and a probe
  showing the fused operation cannot be interleaved — not merely a stress run that missed.
- `inconclusive` whenever the interleaving could not be forced or observed; say which and why.
