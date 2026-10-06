---
name: cwe-77-command-injection-generic
description: Argument or option injection into a program started without a shell. Use this when the finding is CWE-77/88 and no shell parses the value.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-77 / CWE-88: Command and argument injection (no shell)

## Use this skill when

- The finding is classified CWE-77 or CWE-88, or names argument, option or flag injection.
- An untrusted value becomes an element of an argument vector (`execFile`, `subprocess.run([...])`,
  `ProcessBuilder(list)`, list-form `system` / `open '-|'`) and can begin with `-` or `--`.
- A value is placed into a command-like mini language that is not a shell (an SCM refspec, an
  `ssh` host, a `tar` / `rsync` / `find` expression).

## Do not use this skill when

- A shell parses the command line (`shell=True`, `exec`, backticks, `sh -c`) — use
  `cwe-78-os-command-injection`.
- The value is evaluated as program source — use `cwe-94-code-injection`.

## When another skill also applies

- `cwe-78-os-command-injection` also fires on any process-launch finding. **That skill wins**
  whenever a shell is the first interpreter of the value; this skill wins only when the value
  arrives as one argv element and the risk is how the *program* parses its options.
- Use `probe` for source integrity and evidence rules.

## Procedure

**Sink.** A process launch where an untrusted value occupies an argv position the program parses
as an option: `execFile("scm", ["log", user])`, `subprocess.run(["tar", "-cf", out, user])`,
list-form `system("curl", $url)`.

**Guard.** Look for an end-of-options marker (`--`) placed *before* the value, a prefix check
that rejects a leading `-`, a strict allowlist or format check (`^[A-Za-z0-9._/]+$`), or a value
rewritten to a safe form (`./` prepended to a relative path).

**Neutralized when.** The value cannot be read as an option: `--` precedes it and the program
honours `--`, or validation rejects every value starting with `-`, or the value is chosen from a
fixed set. Quoting is irrelevant here; there is no shell.

## Oracle

Condition: **the target program interpreted the untrusted value as an option.** Choose an inert
option whose effect is observable inside the sandbox and touches only a probe-owned path, for
example an output-file option pointing at `/tmp/harness_arg_<nonce>`, or a harmless option that
changes the program's output in a recognizable way (`--version`, `--help`). Never pick an option
that runs a further command. Map the result onto `HARNESS_PROBE` (see `probe`):

- `target_reached`: the real function built and launched (or refused) the argv with the
  option-shaped value. A program exiting non-zero after parsing still counts.
- `oracle_valid`: the option is inert, accepted by the sandbox's copy of the program, and
  touches only a probe path.
- `vulnerability_observed`: the option's effect appears: the marker file exists, or the output
  shows the option's signature rather than the normal result for a file with that name.
- `positive_control`: the same program run directly by the probe with the option as an argv
  element produces the effect, proving the program and option exist in the sandbox.
- `negative_control`: a benign value (an existing file or ref) through the target produces the
  normal result and no marker.

If the program is absent from the sandbox, say so and stay `inconclusive`; do not substitute a
different program.

## Language notes

- **Python:** `subprocess.run([...])` with `shell=False`; check for `"--"` in the list before the value.
- **JavaScript:** `child_process.execFile` / `spawn` without `shell: true`; `spawn(..., {shell: true})` is CWE-78.
- **Java:** `ProcessBuilder(List)` / `Runtime.exec(String[])`; `Runtime.exec(String)` splits on spaces without a shell, so a space in the value can add argv elements.
- **Perl:** list-form `system LIST` and `open($fh, '-|', @cmd)` avoid the shell; a one-element list with metacharacters falls back to the shell (CWE-78).

## Pitfalls

- Programs differ: some stop option parsing at the first non-option, some accept options anywhere,
  some ignore `--`. Read the program's behaviour in the sandbox rather than assuming.
- A file literally named `-x` existing in the working directory is a valid benign negative only
  if the target passes it through unchanged.
- Do not count a usage error as `vulnerability_observed`; it shows parsing, not the option's effect.

## Verdict guidance

- `potentially_exploitable`: the attacker controls an argv element that reaches an option
  position with no `--` / prefix guard, and the probe observed an option's effect.
- `likely_not_exploitable`: cite the `--` marker, the leading-dash rejection or the allowlist
  line, with a complete probe showing the option-shaped value treated as data or rejected.
- `inconclusive`: the program is missing in the sandbox, or its option semantics were not observed.
