---
name: cwe-22-path-traversal
description: Recognize path traversal sources, sinks, and containment checks, and define a deterministic
  oracle. Use this when the finding is CWE-22 or untrusted input becomes part of a filesystem path.
metadata:
  owner: appsec
  version: 2.0.0
---

# CWE-22: Path traversal

## Use this skill when

- The finding is classified CWE-22, or names path traversal or directory traversal.
- A caller-supplied name is joined onto a base directory and opened.
- An archive entry name or upload filename is used as a path.

## Do not use this skill when

- The path is fixed and the untrusted value is only file *contents*.
- The value reaches a URL fetch rather than the filesystem — use `cwe-918-ssrf`.

## When another skill also applies

- `cwe-918-ssrf` also fires when the caller-chosen value is a URL whose fetcher accepts `file:`, so one value both picks a destination and names a path, and each skill redirects to the other. **That skill wins** whenever a URL resolver stands between the value and the filesystem: the fetcher owns the sink, so the oracle is about the destination the code was willing to resolve, not about a base directory a name escaped.

## Procedure

**Sink.** Opening/reading/writing a path built from untrusted input: `open(base + name)`,
`new File(dir, name)`, `fs.readFile(path)` where `name` can contain `../` or an absolute path.

**Source.** Untrusted filename/path segments.

**Neutralized when.** The code canonicalizes the path and verifies it stays within the intended
base directory (realpath prefix check), or strips/refuses separators and parent references.

## Oracle

Condition: **the resolved path escaped the intended base directory.** At run time, create a
temp dir holding `base/inside.txt` and, beside `base/`, `outside.txt` containing a unique
nonce. Point the real callable at that base through its own parameters or configuration.
Map the result onto `HARNESS_PROBE` (see `probe`):

- `target_reached`: the real callable ran with a traversal input shaped like the finding
  (`../outside.txt`, an absolute path, an encoded variant). Returning content, returning
  nothing, or raising its own containment error all count; a confining (fixed) target is
  `target_reached: true`, `vulnerability_observed: false`.
- `vulnerability_observed`: the bytes the callable returned or opened contain the nonce.
- `positive_control`: the same check detects the nonce in `outside.txt` read by its direct path.
- `negative_control`: the callable given `inside.txt` returns its contents and the check stays silent.

Never read real system files. If the finding involves links, create them only in the temp
dir and remove them as `probe` describes.
