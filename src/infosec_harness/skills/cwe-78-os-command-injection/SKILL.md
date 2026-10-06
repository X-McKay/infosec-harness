---
name: cwe-78-os-command-injection
description: Recognize OS command injection sources, sinks, and sanitizers, and define a canary oracle.
  Use this when the finding is CWE-78 or untrusted input reaches a shell.
metadata:
  owner: appsec
  version: 2.0.0
---

# CWE-78: OS command injection

## Use this skill when

- The finding is classified CWE-78, or names command or shell injection.
- A value the caller supplies reaches a shell-interpreting call (`shell=True`, `os.system`, backticks, `sh -c`).
- A command string is assembled by concatenation rather than an argument list.

## Do not use this skill when

- The value reaches a SQL driver — use `cwe-89-sql-injection`.
- The value is evaluated as program source — use `cwe-94-code-injection`.
- The call already uses an argument vector with no shell.

## When another skill also applies

- `cwe-94-code-injection` also fires when the value is interpolated into a string the language evaluates and the evaluated code then runs a shell command, so both criteria hold and each skill redirects to the other. **That skill wins**: the evaluator consumes the value first, and shell metacharacters aimed at a string the language parses first are a syntax error rather than a payload.
- `cwe-89-sql-injection` also fires when the shell command is a database client carrying the value inside its SQL. **This skill wins** by the same first-interpreter rule: the shell parses the command line before the database sees a query, so the quoting context to match and the canary to observe are both the shell's.

## Procedure

**Sink.** Passing a string to a shell: `os.system`, `subprocess.*(..., shell=True)`,
`Runtime.exec("sh -c ...")`, `child_process.exec`, backticks / `system()` in Perl, where the
command string includes untrusted input.

**Source.** Untrusted values reaching the command string.

**Neutralized when.** The program uses the argument-vector form with no shell
(`subprocess.run([...], shell=False)`, `ProcessBuilder(list)`, `execFile`) and the untrusted
value is a single argument, or the value is strictly allowlisted.

## Oracle

Condition: **the shell interpreted attacker text and ran an injected marker command.** The
marker command only creates `/tmp/harness_canary_<nonce>`: no network, data access or
destructive action. Map the result onto `HARNESS_PROBE` (see `probe`):

- `target_reached`: the real function ran with the payload and built or rejected the command,
  including when an allowlist refuses the value or the command fails.
- `vulnerability_observed`: the canary exists after the target call and did not before.
- `positive_control`: the command string the sink line would build with that payload, run
  directly through `sh -c`, creates a separate canary. This proves the payload fits the
  quoting context.
- `negative_control`: a benign value (an existing file name) runs normally through the
  target and creates no canary.

**Match the payload to the sink's quoting context — read the line before choosing it.** This is
the most common way a canary probe fails on a genuinely vulnerable target, and the failure is
silent: the shell rejects the command, the canary is absent, and the run is indistinguishable
from the code having resisted.

- The value is concatenated **bare** (`exec("wc -l " + path)`): inject a separator and nothing
  else — `/dev/null; touch /tmp/harness_canary_<nonce>`. Do **not** add a leading quote; there
  is no quote to escape, and an unmatched one makes the whole command a syntax error.
- The value sits inside **single quotes** (`exec("wc -l '" + path + "'")`): close the quote
  first — `'; touch /tmp/harness_canary_<nonce>; :'` — and leave the quoting balanced.
- The value sits inside **double quotes**: `"; touch /tmp/harness_canary_<nonce>; :"`, or use
  `$(touch ...)`, which needs no separator at all.

Give the command something valid to operate on before the separator (`/dev/null`, an existing
path) so a failure of the *original* command cannot be mistaken for a failure of the injection.
