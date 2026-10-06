---
name: cwe-401-missing-release-of-memory
description: Recognize memory and handle/descriptor leaks and define a bounded-iteration growth oracle.
  Use this when the finding is CWE-401/772/775 or a resource is acquired on a path that never releases it.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-401: Missing release of memory after effective lifetime

Covers CWE-772 (missing release of any resource after lifetime) and CWE-775 (missing release of
file descriptors / handles).

## Use this skill when

- The finding is CWE-401, 772 or 775, or names a memory leak, resource leak, or fd/handle leak.
- A resource is acquired (`malloc`/`open`/`socket`/connection/lock) on a path that can return or
  throw before releasing it, so repeated calls accumulate the resource.

## Do not use this skill when

- The resource is freed and then used — use `cwe-416-use-after-free`.
- The single-call allocation is attacker-sized, not accumulated — use
  `cwe-400-uncontrolled-resource-consumption` / CWE-789.

## When another skill also applies

- `cwe-400-uncontrolled-resource-consumption`: a single huge allocation. **This skill wins** when
  the hazard is *accumulation across calls* (each call leaks a bounded amount); `cwe-400` wins when
  one call sizes the resource from input.
- `cwe-416-use-after-free`: freed-then-used. **That skill wins** when there is a use after free;
  this one is about never freeing at all.

## Procedure

**Sink.** An acquire with no matching release on some path: `malloc`/`strdup` with an early
`return`/`throw` before `free`; `open`/`fopen`/`socket`/`connect` without `close` on an error
branch; an added listener/timer never removed; a lock acquired and not released on a failure path.

**Guard.** RAII / `with` / `try-finally` / `defer` that releases on every path, a single exit that
frees, or an owner that guarantees release (context manager, smart pointer, pool with return).

**Neutralized when.** Every acquire has a release on all paths (including early return and
exception), or ownership transfers to something that releases it.

## Oracle

Condition: **a bounded number of repeated calls leaves resource usage growing roughly linearly with
call count, while a non-leaking control stays flat.** Measure growth over a *small fixed* iteration
count; never loop until the system runs out.

- Call the real callable a fixed small number of times (e.g. 50, then 100) on the leak-triggering
  path and measure the resource after each batch: RSS/allocated bytes for memory, or open-fd count
  (`len(os.listdir('/proc/self/fd'))` on Linux, or `psutil`/`lsof`-style counts) for descriptors.
- The leak-triggering path is often the *error* path — supply input that makes the function return
  early (missing file, parse error) so the acquire happens but the release is skipped.
- Compare the per-iteration growth against a control that takes the releasing path; the control must
  stay flat.

Map onto `HARNESS_PROBE` (see `probe`):

- `target_reached`: the real callable ran the acquire path the stated number of times, including
  when it releases correctly.
- `oracle_valid`: resource usage was sampled at two+ iteration counts under a fixed cap and the
  per-call growth is computed; the run stayed well inside the budget.
- `positive_control`: a deliberately leaking equivalent shows linear growth with call count.
- `negative_control`: a correctly releasing equivalent shows flat usage across the same counts.
- `vulnerability_observed`: the real target showed sustained per-call growth on the triggering path.

A target that releases on every path is `target_reached: true, vulnerability_observed: false`.

## Language notes

- **C:** count `malloc`/`free` by interposing wrappers, or use ASan's leak detector
  (`-fsanitize=address` with `ASAN_OPTIONS=detect_leaks=1`; LSan support depends on the platform —
  confirm it runs, else fall back to counting). `gcc`/`make` are present.
- **Python:** fds via `/proc/self/fd`; memory via `tracemalloc` snapshots or RSS. A GC run can mask
  pure-Python object growth, so for memory prefer fds/externals or force `gc.collect()` between
  samples. `ResourceWarning` on unclosed files is a strong hint.
- **Java:** heap via `Runtime.freeMemory` after `System.gc()` is noisy; prefer handle counts or a
  leak-detection tool. JS: `process.memoryUsage()` and listener counts.

## Pitfalls

- GC and allocator caching make a single memory reading meaningless; the signal is *sustained
  growth proportional to iterations*, with the control flat.
- Keep iteration counts small and fixed — never "loop until OOM/EMFILE". A budget kill proves a
  limitation, not the leak.
- The leak usually lives on the error path; exercising only the happy path gives a false negative.
- One-time caches/pools grow once then plateau — that is not a leak; require continued growth.

## Verdict guidance

- `potentially_exploitable` needs a complete probe showing linear per-call growth through the real
  target on the triggering path, both controls green.
- `likely_not_exploitable` needs the finally/RAII/close guard cited at its line and a probe showing
  flat usage across iterations.
- `inconclusive` when growth cannot be separated from GC/allocator noise within a safe iteration
  cap; say which.
