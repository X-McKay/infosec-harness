---
name: cwe-611-xxe
description: "Recognize XML external entity sinks and define a sandbox-file oracle."
---

# CWE-611: XML external entity (XXE)

**Sink.** Parsing untrusted XML with a parser that resolves external entities/DTDs:
misconfigured `lxml`, `DocumentBuilderFactory` without secure processing, `XMLReader` with
external entities enabled.

**Source.** Untrusted XML documents.

**Neutralized when.** The parser disables DTDs / external entity resolution (secure-processing
feature on, `resolve_entities=False`, `disallow-doctype-decl`).

## Oracle

The exploit condition is **"the parser resolved an external entity to content it should not
have."** Keep it entirely inside the sandbox:

- Create a marker file under `/tmp` containing `HARNESS_ORACLE::<nonce>`.
- Build an XML document whose DOCTYPE defines an external entity pointing at that sandbox file
  (a `file://` reference under `/tmp`) and expands it in the body.
- Print the precondition marker, then parse with the target callable and read the parsed text.
  Fire the oracle when the marker file's contents appear in the parsed result. A hardened
  parser leaves the entity unresolved or errors — a valid negative.

Reference only the sandbox marker file; never point an entity at real system files or a
network URL.
