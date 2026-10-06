---
name: cwe-732-incorrect-permission-assignment
description: Files, directories or sockets created with overly broad permissions. Use this when the finding is CWE-732/276/277/278.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-732: Incorrect permission assignment for critical resource

## Use this skill when

- The finding is classified CWE-732, CWE-276 (incorrect default permissions), CWE-277
  (insecure inherited permissions) or CWE-278 (insecure preserved inherited permissions).
- Code creates or changes a file, directory, key file, log, cache or UNIX socket with a mode
  that grants group or other users read or write (`chmod 0666`, `umask(0)`, `os.makedirs(...,
  0o777)`, `fs.writeFileSync(p, d, {mode: 0o666})`, `Files.setPosixFilePermissions` with
  `OTHERS_WRITE`).

## Do not use this skill when

- Another user can pre-create or replace the path before the open — use
  `cwe-377-insecure-temporary-file`.
- The resource is served over HTTP to the wrong audience — use
  `cwe-668-exposure-of-resource-to-wrong-sphere`.

## When another skill also applies

- `cwe-16-security-misconfiguration` routes CWE-276 here; **this skill wins** for file and
  socket modes.
- `cwe-377-insecure-temporary-file` **wins** for a race on a predictable name; this skill
  wins when creation is atomic but the resulting mode is too broad.

## Procedure

**Sink.** The creation or mode change: `open`/`os.open` with a mode, `chmod`, `mkdir`, `umask`
before creation, `socket.bind` on a filesystem path, archive extraction that preserves modes.

**Guard.** An explicit restrictive mode (`0o600` for secrets, `0o700` for private directories),
`umask(0o077)` around creation, `chmod` immediately after an exclusive create, Java
`PosixFilePermissions.fromString("rw-------")`.

**Neutralized when.** The resource's effective mode after creation grants no write to group or
other, and no read to them for secrets. The effective mode is the requested mode masked by the
process umask, so read both.

**Source.** Usually not an input: the attacker is another local account that can then read or
modify the resource. Name what that account gains.

## Oracle

Condition: **the resource the real code created has group or other permission bits the
resource must not have.** Run the target in a directory the probe creates, set a known umask
(`0o022`, a common default) before the call so the result does not depend on the sandbox, and
`stat` the created path.

- `target_reached`: the real function ran and created (or attempted to create) the resource.
- `oracle_valid`: a known umask was set before the call and `stat` reads the path the target
  created.
- `vulnerability_observed`: `stat` shows `S_IWOTH` or `S_IWGRP`, or `S_IROTH`/`S_IRGRP` for a
  secret, on the resource the target created.
- `positive_control`: a file the probe creates with mode `0o666` under umask `0` shows the bit
  and the check fires.
- `negative_control`: a file the probe creates with mode `0o600` leaves the check silent.

Record the umask used. If the target sets its own umask, that is the behaviour under test;
do not override it after the call starts.

## Language notes

- **Python**: `os.open(p, flags, 0o666)`, `os.chmod`, `os.umask(0)`, `os.makedirs(mode=)`,
  `Path.write_text` (umask default), `socket` with `bind(path)` then no `chmod`.
- **JavaScript**: `fs.writeFileSync(p, d, { mode })`, `fs.chmodSync`, `fs.mkdirSync(p, { mode })`,
  `process.umask`; `net.createServer().listen(path)` socket modes.
- **Java**: `Files.setPosixFilePermissions`, `File.setWritable(true, false)`,
  `File.setReadable(true, false)`.
- **Perl**: `umask 0`, `chmod 0666, $file`, `sysopen($fh, $p, O_CREAT|O_WRONLY, 0666)`,
  `mkdir $d, 0777`. Use the built-in `stat` and `Fcntl ':mode'` constants in the probe.

## Pitfalls

- Reporting a requested mode without masking by the umask actually in effect.
- A public file that is meant to be public (a static asset) is not a finding.
- Windows ACLs are out of scope for a POSIX stat; say so if the target is Windows-only.

## Verdict guidance

- `potentially_exploitable`: the created resource carries the forbidden bit under a common
  umask, and you can name what another local account can read or change.
- `likely_not_exploitable`: the cited explicit mode or umask produced a restrictive result,
  with both controls passing.
- `inconclusive`: the mode depends on a deployment umask or ACL you cannot observe.
