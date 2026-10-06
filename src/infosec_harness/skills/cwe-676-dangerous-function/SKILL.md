---
name: cwe-676-dangerous-function
description: Recognize calls to inherently risky functions, route them to the matching weakness, and
  decide exploitability from the call's inputs, not its name. Use this when the finding is CWE-676 or CWE-242.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-676: Use of potentially dangerous function

## Use this skill when

- The finding is classified CWE-676 or CWE-242 (inherently dangerous function), or a scanner
  flagged a call by name (`eval`, `pickle.loads`, `mktemp`, `gets`, `strcpy`, `system`).

## Do not use this skill when

A specific weakness explains the danger; load that skill and use this one only for routing:

- Evaluation — `cwe-94-code-injection`; shell — `cwe-78-os-command-injection`.
- Deserialization — `cwe-502-deserialization`; reflection — `cwe-470-unsafe-reflection`.
- Temporary names — `cwe-377-insecure-temporary-file`.
- File modes — `cwe-732-incorrect-permission-assignment`.

## When another skill also applies

- The specific skill **wins**: its oracle observes the actual hazard. This skill decides
  whether the flagged call carries attacker influence at all, and supplies the rule below.

**Rule: presence alone is not exploitability.** A dangerous function called only with
constants, trusted configuration or validated values is a code-quality note, not a
vulnerability. The verdict depends on whether attacker-influenced data reaches the risky
parameter and what the function then does with it.

## Procedure

**Sink.** The flagged call and the specific parameter that makes it dangerous (the format
string, the buffer length, the evaluated text, the file name).

**Guard.** Constant arguments; bounds checks; a validated or typed value; an equivalent safe
function used on the attacker-reachable path.

**Neutralized when.** No attacker-influenced value reaches the dangerous parameter, or the
value is constrained so the dangerous behaviour cannot occur. Cite the line that fixes it.

**Source.** Trace backwards from the dangerous parameter to every caller.

## Oracle

Use the routed skill's oracle when one applies. Otherwise:

Condition: **attacker-shaped input through the real entry point makes the function exhibit
its dangerous behaviour** (for example, a format directive interpreted, a length exceeded and
detected, a deprecated parser accepting an input the safe one refuses).

- `target_reached`: the real entry point ran with the attacker-shaped value.
- `vulnerability_observed`: the dangerous behaviour was observed in the target's output or
  state.
- `positive_control`: the same function called directly with the same value shows the
  behaviour.
- `negative_control`: a benign value through the target shows normal behaviour.

If the trace shows only constants reach the call, probe the real entry point with varied
inputs to show the call's argument does not change, and report `vulnerability_observed: false`.

## Language notes

- **Python**: `eval`, `exec`, `pickle`, `marshal`, `yaml.load`, `tempfile.mktemp`,
  `os.system`, `input()` in Python 2, `assert` used for security checks (removed under `-O`).
- **JavaScript**: `eval`, `new Function`, `setTimeout(string)`, `child_process.exec`,
  `Buffer(n)` (uninitialized memory in old Node), `vm.runInContext` as a sandbox.
- **Java**: `Runtime.exec`, `Thread.stop`, `ObjectInputStream`, `java.util.Random` for secrets,
  `MessageDigest.getInstance("MD5")` for passwords.
- **Perl**: two-argument `open`, string `eval`, backticks, `system` with one string,
  `rand` for secrets, `$sth->do` with interpolation.
- **C / native extensions**: `gets`, `strcpy`, `sprintf`, `strcat`, `scanf("%s")`; these need a
  compiler and a harness the sandbox may not have, so the result is often `inconclusive`.

## Pitfalls

- Reporting the scanner's rule name as the evidence. The scanner flagged a name; the verdict
  needs a data flow.
- Ignoring that a safe wrapper is used on the reachable path while the flagged call is dead code.

## Verdict guidance

- `potentially_exploitable`: attacker input reaches the dangerous parameter and the routed or
  generic oracle fired.
- `likely_not_exploitable`: only constants or validated values reach it (cite the line), with
  a complete probe showing the argument does not follow the input.
- `inconclusive`: callers are outside the repository or the runtime cannot be built.
