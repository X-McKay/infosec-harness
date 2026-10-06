---
name: cwe-476-null-pointer-dereference
description: Null, None or undefined dereferences of unchecked external values. Use this when the finding is CWE-476/690.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-476: NULL pointer dereference

Covers CWE-690 (unchecked return value becoming a null dereference). In managed languages the
same shape is an unchecked `None`/`null`/`undefined` from external input.

## Use this skill when

- The finding is CWE-476 or 690, or names a null-pointer / `NoneType` / `undefined` dereference.
- An external value or an API return that can be `NULL`/`None`/`undefined` is dereferenced
  (`p->f`, `x.attr`, `obj.method()`, `d["k"]`, `a[i]`) without a presence check.

## Do not use this skill when

- The pointer is dangling (freed), not null — use `cwe-416-use-after-free`.
- The missing value causes a wrong computation rather than a dereference — use
  `cwe-682-incorrect-calculation`.
- The general question is whether input is validated at all — start at
  `cwe-20-improper-input-validation`, which routes here when the sink is a dereference.

## When another skill also applies

- `cwe-20-improper-input-validation` is the generic router. **This skill wins** once the
  observable consequence is a null dereference; use `cwe-20-improper-input-validation` only to decide routing.
- `cwe-416-use-after-free` also fires when a freed pointer is nulled then used. **That skill wins**
  when the address is a freed object; this one when the value is genuinely null.

## Procedure

**Sink.** Dereferencing a value that external input can make absent: `ptr->field` / `*ptr` in
C/C++ after a `malloc`/`strchr`/`getenv`/lookup that can return `NULL`; `value.attr` /
`value["k"]` / `value()` in a managed language on a field that may be missing from parsed JSON,
a DB row, a regex match, or an env var.

**Guard.** A presence check on the exact value before the dereference on that path: `if (!p)
return;`, `if x is None`, `obj?.field`, `dict.get(k, default)`, schema validation that rejects
the missing field, or a type that cannot be null.

**Neutralized when.** The value is checked (or defaulted) before use, a schema/validator rejects
absent input upstream, or the type system guarantees presence (non-null type, required field).

## Oracle

Condition: **the dereference executed on an absent value and faulted.** The observable is a
specific fault, not merely an exception somewhere:

- **Managed languages (deterministic).** Drive the real callable with input that omits the field
  (or sets it null). `vulnerability_observed` is a raised `AttributeError`/`TypeError`
  (`'NoneType' object has no attribute`), `KeyError`, or JS `TypeError: cannot read properties of
  undefined` *at the finding's sink line*. Confirm the line with the traceback/stack. A validated
  target that raises its *own* clear rejection (e.g. `ValueError("field required")`) before the
  sink is `target_reached: true, vulnerability_observed: false`.
- **C/C++.** A dereference of `NULL` gives SIGSEGV (exit 139); ASan/UBSan
  (`-fsanitize=null`) reports it precisely. Confirm the sanitizer or the signal with a tiny probe.

Map onto `HARNESS_PROBE` (see `probe`):

- `target_reached`: the real entry point ran with the missing-value input, including when its own
  check rejects it first.
- `oracle_valid`: the detector distinguishes the sink fault from an unrelated error (match the
  exception type and the sink line, or the SIGSEGV/UBSan report).
- `positive_control`: the dereference performed directly on an absent value raises the same fault.
- `negative_control`: a complete, valid input runs the target to a normal result with no fault.
- `vulnerability_observed`: the missing-value input through the real target faulted at the sink.

## Language notes

- **Python:** distinguish the sink `AttributeError`/`KeyError` from an unrelated one — assert the
  traceback's last frame is the finding's line. `dict.get` and `try/except` around the sink are
  guards, not bugs.
- **JS/TS:** optional chaining (`?.`) and default params are guards; `undefined` from a missing
  property or a non-matching `find()` is the classic source.
- **C/C++:** check a library's documented `NULL`-on-failure return against whether the code tests
  it. `malloc` returning `NULL` under a bounded input is hard to force; prefer a function whose
  `NULL` return is input-driven.
- A caught-and-handled null (the program degrades gracefully) is not exploitable; it is at most a
  robustness issue unless the finding claims a security consequence.

## Pitfalls

- Any code can raise *some* exception; only a fault of the right kind at the sink line supports
  the verdict. A generic `except Exception` upstream may already neutralize it.
- A crash-only (DoS) consequence is the usual impact here; do not overstate it as memory
  corruption unless the finding and evidence support that.

## Verdict guidance

- `potentially_exploitable` needs a complete probe where the missing-value input faulted at the
  sink through the real target, both controls green, and a stated impact (crash/DoS, or worse if
  justified).
- `likely_not_exploitable` needs the presence check or schema guard cited at its line and a probe
  showing the input is handled.
- `inconclusive` when the sink line cannot be reached deterministically or the fault cannot be
  attributed; say which.
