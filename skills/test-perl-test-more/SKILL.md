---
name: test-perl-test-more
description: How to write a probe as a Test::More script that emits the oracle markers. Use this when
  authoring or repairing a probe for a Perl repository.
metadata:
  owner: appsec
  version: 1.0.0
---

# Probes in Test::More

## Use this skill when

- You are writing or repairing a probe and the repository's test framework is Test::More or Test2.

## Do not use this skill when

- The repository uses a different framework; load that `test-*` skill.
- You have not yet read `probe-oracle-protocol`; read it first.



## Safety constraints

- The test must run to completion and print its markers whether or not the exploit condition holds. Never let an assertion failure be the signal.
- Confine every effect to the sandbox temp dir. The probe has no network.
- Do not mock, stub, or reimplement the sink: call the smallest real callable that owns it.

## Completion criteria

- The probe prints the precondition marker at the moment it reaches the sink call.
- It emits the oracle signal only when the exploit condition actually holds.
- It runs to completion and exits cleanly either way.
- Framework output is not captured away, so the markers reach the runner's stdout.
