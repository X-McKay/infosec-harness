---
name: cwe-125-out-of-bounds-read
description: C/C++ reads past a buffer boundary. Use this when the finding is CWE-125/126/127 or an index or length can exceed the buffer.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-125: Out-of-bounds read

Covers the buffer-read family: CWE-126 (buffer over-read) and CWE-127 (buffer under-read).

## Use this skill when

- The finding is CWE-125, 126 or 127, or names a buffer over-read / under-read / info leak.
- An attacker-influenced index or length drives a load: `buf[i]`, `*p`, `memcpy(dst, src, n)`
  where `n` exceeds the source, `strlen`/`printf("%s")` on a non-terminated buffer.

## Do not use this skill when

- The access *writes* past the end — use `cwe-787-out-of-bounds-write` (higher severity).
- The source buffer was freed — use `cwe-416-use-after-free`.
- The length is a wrapped computation never used in an access — use `cwe-190-integer-overflow`.

## When another skill also applies

- `cwe-787-out-of-bounds-write` also fires when one loop both reads and writes out of bounds.
  **That skill wins**: a write corrupts memory and is the graver sink. Probe the write.
- `cwe-190-integer-overflow` also fires when a wrapped length drives the read. **This skill
  wins** once the over-read is the observable consequence; cite both CWEs, probe the read.

## Procedure

**Sink.** A load that can reach outside the source object: `buf[i]`/`*p` with untrusted `i`/`p`,
`memcpy`/`memmove` with a count larger than the source, `strlen`/`str*`/`printf("%s", p)` on a
buffer with no NUL in range, or returning more bytes than were written.

**Guard.** A bound check against the source object's real length on the input path, with the
right relation, before the load; for string APIs, a guaranteed NUL terminator within capacity.

**Neutralized when.** The read length is clamped to the source size, the index is range-checked,
the buffer is explicitly NUL-terminated, or a length-bearing type replaces the raw pointer.

## Oracle

Condition: **a load returned bytes from outside the source object.** Use a small bounded input
that crosses the boundary by a few bytes. Plant a known sentinel value immediately past the
source buffer so an over-read is *observable as data*, not just as a possible crash.

Establish the detector at run time; do not assume ASan:

- **Sentinel/canary (portable).** Allocate the source adjacent to a sentinel region holding a
  unique nonce (struct field after the array, or a flanking `malloc` region). If the target's
  output or return value contains the nonce, bytes from past the end leaked.
- **ASan (when available).** Compile with `gcc -fsanitize=address -g`; a confirmed over-read
  produces an `AddressSanitizer: ... overflow` report. Verify ASan works with a tiny probe first.
- **Controlled crash.** A read far past the end into an unmapped page gives SIGSEGV (exit 139);
  use only when the leak is not otherwise observable, and keep the offset bounded.

Map onto `HARNESS_PROBE` (see `probe`):

- `target_reached`: the real function ran with the finding-shaped input, including when its
  bound check clamps the read and returns normally.
- `oracle_valid`: the sentinel/ASan/signal detector is in place and inspected.
- `positive_control`: a deliberate over-read through the same detector surfaces the nonce
  (or fires ASan/crash), proving the detector works.
- `negative_control`: an in-bounds input returns only intended bytes; the nonce never appears.
- `vulnerability_observed`: the finding-shaped input through the real target surfaced the nonce
  (or fired ASan/crash).

`target_reached` means the real target ran, not that it over-read; a clamping target is
`target_reached: true, vulnerability_observed: false`.

## Language notes

- **C/C++:** use `gcc`/`make` from the workspace; the ASan runtime ships with the compiler but
  compilation needs C headers — report a toolchain gap rather than guessing. `-O0 -g` keeps the
  sink line meaningful. Uninitialized padding can mimic a leak; use a distinctive nonce.
- Managed languages rarely have raw over-reads; a report usually points at a native buffer API,
  a `ctypes`/FFI call, or a slice with an unchecked length. Scope to that boundary.

## Pitfalls

- A crash-only oracle cannot distinguish an over-read from an over-write; prefer the data
  sentinel when the question is information disclosure.
- Compiler optimization may reorder or elide the sentinel; keep it `volatile` or use ASan.
- Zeroed memory next to the buffer can hide a leak — choose a nonce that is not all zeros and
  not present in the legitimate input.

## Verdict guidance

- `potentially_exploitable` needs a complete probe where the bounded finding-shaped input
  surfaced out-of-bounds bytes through the real target, both controls green.
- `likely_not_exploitable` needs the bound/terminator guard cited at its line and a probe showing
  the read is confined.
- `inconclusive` when the toolchain cannot build the target or no detector holds; name the gap.
