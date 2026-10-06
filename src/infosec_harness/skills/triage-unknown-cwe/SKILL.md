---
name: triage-unknown-cwe
description: 'A weakness with no cwe-* skill: map it to a family, sink, guard and oracle, or show it is unobservable here. Use this when no cwe-* skill matches.'
metadata:
  owner: appsec
  version: 1.0.0
---

# Triage of an unfamiliar weakness class

## Use this skill when

- The finding's CWE, or its description, matches no `cwe-*` skill in the catalog.
- The finding has no CWE at all and you must decide what class it belongs to.

## Do not use this skill when

- A `cwe-*` skill matches: load it; its oracle and controls take precedence over this one.

## Ground rules

Skills carry expertise and grant no permissions. A configured name is not execution evidence:
a security header in a config file, a library named in a manifest or a flag in CI shows
intent, not behaviour. Payloads stay minimal and diagnostic, use nonce markers, and target
nothing outside the sandbox (`investigate`).

## Procedure

1. **Restate the claim** as "the attacker controls X, which reaches Y, causing Z", with the
   file and line for Y. If you cannot fill X, Y and Z from the source, that is the finding's gap.
2. **Map it to the nearest family** and borrow that family's controls:

| Family | Examples | Observable condition | Borrow controls from |
| --- | --- | --- | --- |
| Injection | CWE-77, 88, 90, 91, 113, 117, 643, 917, 943, 1236, 1336 | attacker text changed the structure the interpreter received | `cwe-89-sql-injection` (trace hook), `cwe-78-os-command-injection` (canary, quoting), `cwe-94-code-injection` |
| Access control | CWE-639, 284, 285, 287, 306, 352, 425, 601, 862, 863 | principal A obtained what only B may | `cwe-22-path-traversal` (inside/outside fixtures), `cwe-918-ssrf` (loopback) |
| Crypto | CWE-295, 321, 326, 327, 328, 330, 338, 347, 916 | real function accepts a forged/unsigned input, emits a weak algorithm, or trusts a bad certificate | `cwe-918-ssrf` (loopback TLS peer) |
| Memory | CWE-119, 120, 125, 134, 190, 415, 416, 476, 787 | crash, guard-page fault or sanitizer report at the target | `lang-c-cpp` |
| Resource | CWE-400, 409, 674, 770, 834, 1333 | cost grows super-linearly with input size | positive control on the same engine |
| Exposure | CWE-200, 209, 312, 319, 532, 538, 548, 798 | a seeded nonce secret appears where the attacker reads | `cwe-22-path-traversal` (nonce file) |
| Logic | CWE-20, 362, 367, 704, 841, 915, 1284, 1321 | a stated invariant is false after the call | `probe` (check the invariant before and after the call) |

3. **Derive sink, guard and neutralized-when** from first principles: the sink is the
   operation where Z happens; the guard is the code that should stop X before it; it is
   neutralized when a precise, checkable condition holds (a bound parameter, an ownership
   check on the resource id, signature verification before use, a size limit before the loop).
   Cite each at its line.
4. **Design the oracle** around an observation the real target produces, never a stand-in:
   - finding-shaped input through the real entry point (`target_reached`);
   - a positive control that makes the same check fire through a deliberate, direct use of the
     same mechanism (owner reads own record; a known catastrophic regex such as `(a+)+$` on the
     same engine; a deliberately unsigned token against a verifier you know accepts it);
   - a negative control where a benign input leaves it silent;
   - for resource classes, compare sizes n, 2n, 4n under an internal time bound well inside the
     command budget, and report the growth, not a single slow run;
   - for races, run a bounded number of attempts and report the rate; a race that never fired
     in the budget is not a blocking condition.
5. **Decide observability.** The class is **not observable here** when the condition needs
   real external hosts or DNS, several machines, production data or configuration absent
   from the repository, privileged kernel or hardware state, timing precision below the
   sandbox's noise (remote timing side channels), user interaction in a real browser, or a
   destructive or weaponized payload. Examples: HTTP request smuggling across a real proxy,
   cache poisoning of a CDN, clickjacking, physical side channels.
   Then return `inconclusive`, state the reason in the summary as a limitation, and report
   the narrower fact you did establish (the guard absent at line N, the algorithm constant at
   line M) without promoting it to exploitability.
6. **Map to `HARNESS_PROBE`** exactly as `probe` defines the five fields, and choose the verdict
   by the rules in `investigate`.

## Never

- Infer exploitability from a CWE label, a scanner's severity or a matching function name.
- Treat a weakness that is merely present (an old dependency version, a weak hash constant) as
  exploitable without showing the attacker-controlled path to it.
- Treat an unexecuted or unobservable path as a blocking condition.

## Completion criteria

- You can name the family, the sink, guard and neutralized-when condition with lines, the
  oracle with both controls, and either the probe you ran or the reason the class is not
  observable in this sandbox.
