---
name: cwe-611-xxe
description: Recognize XML external entity sinks and define a sandbox-file oracle. Use this when the
  finding is CWE-611 or untrusted XML is parsed with entity resolution enabled.
metadata:
  owner: appsec
  version: 2.0.0
---

# CWE-611: XML external entity (XXE)

## Use this skill when

- The finding is classified CWE-611, or names XXE or external entity expansion.
- Untrusted XML reaches a parser whose entity or DTD processing is not disabled.

## Do not use this skill when

- The parser has entity resolution explicitly disabled and the finding is about something else.
- The document is JSON or YAML — use `cwe-502-deserialization`.

## When another skill also applies

- `cwe-502-deserialization` also fires when the XML goes to something that instantiates the types it names rather than to a plain parser, while its own negative criteria send every XML payload back here. **That skill wins** there: the oracle has to observe object construction, which an entity-expansion probe never exercises. Keep this skill when the hazard is the parser resolving an external entity or a DTD.

## Procedure

**Sink.** Parsing untrusted XML with a parser that resolves external entities/DTDs:
misconfigured `lxml`, `DocumentBuilderFactory` without secure processing, `XMLReader` with
external entities enabled.

**Source.** Untrusted XML documents.

**Neutralized when.** The parser disables DTDs / external entity resolution (secure-processing
feature on, `resolve_entities=False`, `disallow-doctype-decl`).

## Oracle

Condition: **the parser resolved an external entity to local file content.** At run time,
create a marker file under `/tmp` containing a unique nonce, and a document whose DOCTYPE
declares an external entity pointing at that file (`file://` under `/tmp`) and expands it
in the body. Map the result onto `HARNESS_PROBE` (see `probe`):

- `target_reached`: the real parse entry point, with its own parser configuration, received
  the document, including when it rejects the DOCTYPE or leaves the entity unresolved.
- `vulnerability_observed`: the nonce appears in the parsed result the target returns.
- `positive_control`: the same document through a parser deliberately configured to resolve
  external entities yields the nonce, proving the document and check work.
- `negative_control`: an equivalent document without the DOCTYPE, holding plain text, passes
  through the target and the nonce is absent.

Point entities only at the probe's marker file; never at system files or network URLs.
