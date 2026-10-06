---
name: lang-shell
description: 'Conventions for shell scripts (sh, bash): interpreters, quoting, expansion sinks and xtrace
  observation. Use this when the finding is in a shell script, Makefile recipe, CI step or hook.'
metadata:
  owner: appsec
  version: 1.0.0
---

# Shell scripts

## Use this skill when

- The finding's sink is in a `*.sh`/`*.bash` file, a script with a shell shebang, a Makefile
  recipe, a CI `run:` step, a git hook or a Dockerfile `RUN` line.

## Do not use this skill when

- Another language builds a command string and hands it to a shell: start from that
  language's skill and `cwe-78-os-command-injection`; return here for the shell's quoting.
- You are planning installs — use `environment`. This skill grants no permissions.

## Recognize the interpreter

- The shebang decides: `#!/bin/sh` is **dash** on Debian (no arrays, no `[[ ]]`, no `$'..'`),
  `#!/bin/bash` or `#!/usr/bin/env bash` is bash. Run the script with that interpreter, never
  a different one: bash and dash parse the same text differently.
- The image has `/bin/bash` and `/bin/sh` (dash), coreutils and `/usr/bin/timeout`. Do not
  assume `zsh`, `ksh`, `busybox`, `jq` or `curl`.
- Entry points: argv (`$1`, `$@`), environment variables, stdin (`read`), file names from
  `find`/globs, CI variables (branch names, PR titles), hook arguments.

## Sinks to note

- `eval`, `sh -c "$x"`, `bash -c`, `source "$x"`, `$(...)`/backticks built from data.
- Unquoted expansions (`rm $f`, `cp $src $dst`): word splitting and glob expansion turn one
  value into several arguments; a value starting with `-` becomes an option (use `--`).
- Arithmetic evaluation runs command substitutions inside array subscripts: `$(( x ))`,
  `[[ $x -eq 1 ]]`, `${arr[$x]}` and `let` all evaluate `x='a[$(cmd)]'` in bash.
- `[ $x = y ]` with unquoted operands (test-operator injection), `read` without `-r`,
  `IFS` changes, `xargs` without `-0`, `trap` strings, and `printf "$x"` (format string).
- Temporary files in `/tmp` with predictable names and no `mktemp` (symlink races).

## Inspect dependencies offline

List every external command the path invokes and check each with `command -v`. A missing
command makes the real script fail before or after the sink; record which.

## Run a probe

Run the real script with finding-shaped input in a scratch directory the probe creates, and
observe with the shell's own trace rather than by replacing commands it calls:

```bash
set -uo pipefail
work=$(mktemp -d) && exec 9>"$work/xtrace"
BASH_XTRACEFD=9 bash -x ./scripts/deploy.sh "$payload" >"$work/out" 2>"$work/err"; rc=$?
```

- `set -euo pipefail` is for scripts you write, but in the probe drop `-e` around the target
  call: its non-zero exit is data, not a probe failure. `set -e` is ignored inside functions
  called from `if`, `&&` or `||`, so do not read it as a guard in the target either.
- `BASH_XTRACEFD` traces bash only; for a dash script use `sh -x` with stderr redirected.
- Sourcing a library (`. lib.sh; func "$payload"`) runs its top-level code; read it first.
- Use the canary file from `cwe-78-os-command-injection`; replacing a command on `PATH` with a
  stub replaces the sink and can only support a positive control, never the observation.
- Run as a subprocess from Python when that makes the controls easier; the line must be last.

## The HARNESS_PROBE line

Values must be the literal words `true` and `false`; validate before printing:

```bash
j() { [ "$1" = 1 ] && echo true || echo false; }
printf 'HARNESS_PROBE {"target_reached":%s,"oracle_valid":%s,"positive_control":%s,"negative_control":%s,"vulnerability_observed":%s}\n' \
  "$(j "$t")" "$(j "$o")" "$(j "$p")" "$(j "$n")" "$(j "$v")"
```

Keep the target's stdout in a file so nothing prints after the line; an `EXIT` trap that
echoes would also break it.

## Common failure modes

- The quoting context of the payload does not match the sink line (see `cwe-78-os-command-injection`): a syntax
  error looks like a clean negative.
- Running a `/bin/sh` script under bash, or the reverse.
- Locale or `IFS` differences between CI and the sandbox: set them as the deployment would.
- Scripts that `cd` or write outside the scratch directory: run them from it with `HOME` set
  to it, and never let them touch original source files.

## When the toolchain is absent

`bash` and `sh` are present; the gap is usually the script's other commands or a different
shell. Verify with `command -v <tool>` for each. If the interpreter (`zsh`, `ksh`, `fish`,
PowerShell) or a command on the path to the sink is missing, do not download it and do not
replace it with a stub that reaches a conclusion. Return `inconclusive`, name the exact missing
tool as the limitation in the verdict summary, and record what reading established.

## Completion criteria

- You can name the interpreter, the expansion or command that is the sink, its quoting
  context, and the trace or canary that observed it.
