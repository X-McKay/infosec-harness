---
name: cwe-377-insecure-temporary-file
description: Predictable or racy temporary file creation. Use this when the finding is CWE-377/379/59/61.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-377: Insecure temporary file

## Use this skill when

- The finding is classified CWE-377, CWE-379 (temporary file in an insecure directory),
  CWE-59 (link following) or CWE-61 (UNIX symbolic link following), or names a temp-file race.
- Code computes a temporary name and opens it later (`tempfile.mktemp`, `File.createTempFile`
  then reopen, `"/tmp/app-" + pid`, `POSIX::tmpnam`), or opens a fixed path in a shared
  directory without exclusive creation.

## Do not use this skill when

- The file is created atomically and exclusively (`mkstemp`, `NamedTemporaryFile`,
  `Files.createTempFile`, `File::Temp->new`, `fs.mkdtemp`) and the finding concerns only its
  mode — use `cwe-732-incorrect-permission-assignment`.
- The path comes from the caller and escapes a base directory — use `cwe-22-path-traversal`.

## When another skill also applies

- `cwe-732-incorrect-permission-assignment` also fires when the temp file is world-readable.
  **This skill wins** when another user can create or replace the path before the target
  opens it; that skill wins when the only problem is the mode after creation.
- `cwe-676-dangerous-function` routes `mktemp`/`tmpnam` here; **this skill wins**.

## Procedure

**Sink.** The open/write of a path whose name is predictable or was checked earlier:
`open(name, "w")` after `mktemp`, `fs.writeFileSync("/tmp/app.lock")`, Perl
`open(my $fh, '>', "/tmp/report.$$")`.

**Guard.** Exclusive creation (`O_CREAT|O_EXCL`, `"x"` mode, `wx` flag, `CREATE_NEW`),
`O_NOFOLLOW`, a private directory created with `mkdtemp` and mode `0700`, the standard
library's secure temp APIs.

**Neutralized when.** The open fails or creates a fresh file when the path already exists
(file or link), or the containing directory is private to the process owner.

**Source.** Another local user or process in the same shared directory; the attacker controls
timing and the pre-existing entry, not an input parameter.

## Oracle

Condition: **when the predicted path already exists, the target writes through it instead
of refusing.** Work only inside a directory the probe creates with `tempfile.mkdtemp()` (or
the language equivalent). Point the target at it through its own parameter or the standard
temp-directory variable (`TMPDIR`, `tempfile.tempdir`, `java.io.tmpdir`). Predict the name the
target will use from its source (fixed name, pid, counter); for random `mktemp` names, call
the target's own name generator only if it is separately exposed, otherwise rely on the
fixed-path or check-then-open window you can reproduce deterministically.

- `target_reached`: the real function ran and attempted its temp-file write in the probe
  directory, including when it raised `FileExistsError` or chose a new name.
- `oracle_valid`: the decoy sits at the path predicted from source, inside the probe directory.
- `vulnerability_observed`: after the call, a probe-owned decoy file (pre-created at the
  predicted path, or the target of a link pre-created there) contains the target's output.
- `positive_control`: a plain non-exclusive `open(predicted, "w")` in the probe writes through
  the decoy and the check fires.
- `negative_control`: with no pre-created entry, the target writes its own file normally and
  the decoy (at a separate path) is untouched.

Create links only inside the probe directory, point them only at probe-owned files, and
remove every link the probe made in a `finally` block (`os.path.lexists`), as `probe` requires.

## Language notes

- **Python**: `tempfile.mktemp` (deprecated), `os.tempnam`, `open("/tmp/x", "w")`; safe:
  `mkstemp`, `NamedTemporaryFile`, `TemporaryDirectory`, `open(p, "x")`.
- **JavaScript**: `fs.writeFile` to `os.tmpdir() + "/name"`; safe: `fs.mkdtemp`, flag `'wx'`.
- **Java**: `File.createTempFile` then `delete()`/re-create, `new File("/tmp/name")`; safe:
  `Files.createTempFile`/`createTempDirectory` with `PosixFilePermissions`.
- **Perl**: `POSIX::tmpnam`, `"/tmp/file.$$"`; safe: `File::Temp` (`tempfile()` with
  `UNLINK`), `sysopen` with `O_CREAT|O_EXCL`.

## Pitfalls

- Using the real `/tmp` or another user's files; stay in the probe directory.
- A random name from `mktemp` is hard to predict in a single run; the race is still real. If
  you cannot reproduce it, cite the non-exclusive open and return `inconclusive` rather than
  claiming safety.
- A sandbox with a private `/tmp` changes the threat; judge the production deployment.

## Verdict guidance

- `potentially_exploitable`: the target wrote through a pre-existing entry at its predicted
  path in a shared directory.
- `likely_not_exploitable`: the cited exclusive-create or private directory refused the
  pre-created entry, with both controls passing.
- `inconclusive`: the name is random and the window could not be reproduced; state it.
