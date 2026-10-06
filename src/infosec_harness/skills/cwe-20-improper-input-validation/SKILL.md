---
name: cwe-20-improper-input-validation
description: Generic input-validation findings; routes to the specific sink skill. Use this when the finding is CWE-20.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-20: Improper input validation

A routing skill. CWE-20 is a weakness *cause*, not a sink. Its main job is to find the concrete
sink the unvalidated input reaches and hand off to that skill; it defines its own oracle only when
no narrower skill fits and the consequence is directly observable.

## Use this skill when

- The finding is classified CWE-20, or says only "improper/insufficient input validation" without
  naming a concrete sink.
- You need to decide which specific skill owns the finding.

## Do not use this skill when

- The finding already names a concrete class (injection, overflow, path traversal, …) — load that
  skill directly.

## When another skill also applies (it almost always does — route to it)

Follow the unvalidated value to what it reaches, and let that skill win:

- Reaches a shell → `cwe-78-os-command-injection`; a SQL driver → `cwe-89-sql-injection`; an
  evaluator → `cwe-94-code-injection`; markup → `cwe-79-xss`; a URL fetch →
  `cwe-918-ssrf`; a filesystem path → `cwe-22-path-traversal`; a deserializer →
  `cwe-502-deserialization`; an XML parser → `cwe-611-xxe`.
- Drives a buffer write/read → `cwe-787-out-of-bounds-write` / `cwe-125-out-of-bounds-read`; an index/size/divisor →
  `cwe-190-integer-overflow`; a dereference of a missing value →
  `cwe-476-null-pointer-dereference`.
- Sizes/repeats work → `cwe-400-uncontrolled-resource-consumption`; a regex →
  `cwe-1333-regex-denial-of-service`; a loop bound → `cwe-835-infinite-loop`; a calculation →
  `cwe-682-incorrect-calculation`.

**The specific sink skill always wins** once you can name the sink: its oracle observes the real
consequence, which a generic validation check cannot. Record the routing decision in the summary.

## Procedure

**Sink.** Whatever operation finally consumes the value — identify it first. If after tracing there
is genuinely no dangerous sink (the value is only stored or echoed as inert data, or fully
validated), the finding is about the *absence of a validation guard* itself.

**Guard.** The validation that should constrain the value: a type/range/length/format check, an
allowlist, a schema, or a parser that rejects malformed input, applied before the sink on that path.

**Neutralized when.** A correct validator rejects out-of-contract input before any sink, or the sink
is inherently safe for every value the input can take.

## Oracle

Prefer the routed skill's oracle. Define one here only when no narrower skill applies **and** the
consequence is observable — otherwise the honest verdict is `inconclusive` (a missing check with no
demonstrable consequence is a hardening gap, not a proven vulnerability).

When you do define it, the condition is: **an out-of-contract input passed the validation boundary
and produced an observable wrong effect** (a state change, an accepted record, a wrong branch) that
an in-contract input does not. Map onto `HARNESS_PROBE` (see `probe`):

- `target_reached`: the real entry point ran with the out-of-contract input, including when it
  rejects it.
- `oracle_valid`: the check observes a concrete contract violation and its effect, not merely that
  the function returned.
- `positive_control`: an input that is unquestionably out of contract produces the wrong effect
  through the relevant path.
- `negative_control`: an in-contract input is accepted and behaves correctly.
- `vulnerability_observed`: the out-of-contract input was accepted and produced the wrong effect
  through the real target.

## Language notes

- The validation idiom varies (pydantic/marshmallow, Bean Validation, JSON Schema, manual guards);
  identify the one the code relies on before judging it missing.
- "Validation exists but is incomplete" (wrong bound, missing case) still routes to the sink skill
  for the consequence of the gap.

## Pitfalls

- Do not stop at "no validation found" — that is a cause. Find the sink or demonstrate a concrete
  effect; otherwise stay `inconclusive`.
- Defense-in-depth gaps with no reachable consequence are not `potentially_exploitable`.
- Resist inventing a consequence the code does not have just to produce a definitive label.

## Verdict guidance

- Usually defer the definitive verdict to the routed sink skill and cite it.
- `potentially_exploitable` (standalone) needs a complete probe where an out-of-contract input
  produced an observable wrong effect through the real target, both controls green.
- `likely_not_exploitable` needs the validator cited at its line and a probe showing out-of-contract
  input is rejected or harmless.
- `inconclusive` when no sink is reachable and no concrete effect can be shown; name the gap as a
  hardening issue rather than overstating it.
