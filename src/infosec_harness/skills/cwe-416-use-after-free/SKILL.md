---
name: cwe-416-use-after-free
description: Recognize use-after-free, double-free and related lifetime sinks in C/C++ and define a
  sanitizer-or-poison oracle. Use this when the finding is CWE-416/415/825 or freed memory is used.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-416: Use after free

Covers CWE-415 (double free) and CWE-825 (expired pointer / dangling dereference).

## Use this skill when

- The finding is CWE-416, 415 or 825, or names use-after-free, double-free or a dangling pointer.
- A pointer is dereferenced or passed to `free` after the object it points to was freed, or a
  freed pointer escapes (stored, returned) and is later used.

## Do not use this skill when

- The pointer was never freed but is out of bounds — use `cwe-787`/`cwe-125`.
- The pointer is `NULL`/`None` rather than dangling — use `cwe-476-null-pointer-dereference`.
- The concern is a leak (memory never freed), not freed-then-used — use
  `cwe-401-missing-release-of-memory`.

## When another skill also applies

- `cwe-476-null-pointer-dereference` also fires when code frees, sets the pointer to `NULL`, then
  dereferences it. **That skill wins** when the dereferenced value is `NULL`; **this skill wins**
  when the pointer still holds the freed address. Read whether the free path nulls the pointer.
- `cwe-362-race-condition` also fires when the free and the use are on different threads. **That
  skill wins** when the bug only manifests under interleaving; keep this skill for a single-threaded
  ordering defect.

## Procedure

**Sink.** A load, store or `free` through a pointer whose object has already been released:
`free(p); ... *p` / `p->field` / `free(p)` again; an iterator used after the container frees it;
a returned pointer into a freed local or a freed cache entry.

**Guard.** The pointer is set to `NULL` immediately after `free` and every later use is
`NULL`-checked; or ownership is clear so no path reaches the pointer after release; or a
refcount/arena guarantees the object outlives every use.

**Neutralized when.** Post-free nulling plus guarded use, single-owner move semantics
(`std::unique_ptr`), or a refcounted/arena allocator removes the dangling window.

## Oracle

Condition: **the program accessed (read, wrote, or re-freed) memory after it was freed.** Drive
the real sequence with bounded input. Establish the detector at run time:

- **ASan (preferred).** `gcc -fsanitize=address -g` reports `heap-use-after-free` or
  `attempting double-free` with both the free and the use stacks. Confirm ASan works with a tiny
  probe (free then read) before relying on it.
- **Poison fill (no ASan).** Wrap allocation so the region is overwritten with a nonce on free
  (or use `MALLOC_PERTURB_`); a later read that returns the nonce, or a value that changed after
  free, shows the stale access. For double-free, instrument the free wrapper to flag a second
  release of the same address.
- **Controlled crash.** A dereference of a freed-then-unmapped region may SIGSEGV; use only as a
  last resort since the allocator often recycles the page silently.

Map onto `HARNESS_PROBE` (see `probe`):

- `target_reached`: the real code ran the allocate/free/use sequence with the finding-shaped
  input, including when a null-after-free guard turns the use into a safe no-op.
- `oracle_valid`: the ASan/poison/free-tracking detector is active and inspected.
- `positive_control`: a deliberate free-then-use (or double free) through the same detector fires
  it, proving it works.
- `negative_control`: a benign sequence with no post-free access leaves the detector silent.
- `vulnerability_observed`: the finding-shaped path through the real target fired the detector.

A target that nulls-and-guards is `target_reached: true, vulnerability_observed: false`.

## Language notes

- **C/C++:** `gcc`/`make` present; ASan runtime ships with the compiler, but compilation needs C
  headers — report a toolchain gap rather than guessing. ASan is far more reliable than
  crash-based detection because freed pages are usually reused, not unmapped.
- Managed languages have no manual free; a report there points at a native extension, a closed
  file/handle reused, or an FFI buffer. Scope to that boundary and model it as the resource there.

## Pitfalls

- Without ASan, the allocator may hand the freed block straight back, so a UAF "works" and reads
  plausible data — the poison fill is what makes the stale read observable.
- A double-free can appear to succeed on some allocators and abort on others; the free-tracking
  wrapper is more deterministic than waiting for an abort.
- Do not run the positive control and claim the target is vulnerable; derive the verdict only
  from the real target's execution.

## Verdict guidance

- `potentially_exploitable` needs a complete probe where the finding-shaped input drove a
  post-free access through the real target, both controls green.
- `likely_not_exploitable` needs the null-after-free / ownership guard cited at its line and a
  probe showing the access is safe.
- `inconclusive` when the toolchain cannot build or no detector can be established; name the gap.
