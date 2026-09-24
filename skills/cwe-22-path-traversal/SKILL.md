---
name: cwe-22-path-traversal
description: "Recognize path traversal sources, sinks, and sanitizers, and define a deterministic test oracle."
---

# CWE-22: Path traversal

**Sink.** Opening/reading/writing a path built from untrusted input: `open(base + name)`,
`new File(dir, name)`, `fs.readFile(path)` where `name` can contain `../` or an absolute path.

**Source.** Untrusted filename/path segments.

**Neutralized when.** The code canonicalizes the path and verifies it stays within the intended
base directory (realpath prefix check), or strips/refuses separators and parent references.

## Oracle

The exploit condition is **"the resolved path escaped the intended base directory."** Observe
it without touching sensitive files:

- Create a sandbox base dir under `/tmp` and, outside it (but still under `/tmp`), a marker
  file whose contents include `HARNESS_ORACLE::<nonce>`.
- Call the target callable with input intended to traverse out of the base to that marker file.
- Fire the oracle (print the marker) when the bytes the code returns/opens are the marker
  file's contents, i.e. the code read outside its base. If the code confined the path, it reads
  nothing or errors — a valid negative.

Everything stays inside the sandbox temp dir; no real system files are involved.
