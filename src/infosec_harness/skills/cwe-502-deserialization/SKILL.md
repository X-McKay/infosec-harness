---
name: cwe-502-deserialization
description: Untrusted bytes deserialized into objects. Use this when the finding is CWE-502 or names unsafe deserialization.
metadata:
  owner: appsec
  version: 2.0.1
---

# CWE-502: Unsafe deserialization

## Use this skill when

- The finding is classified CWE-502, or names unsafe or insecure deserialization.
- Untrusted bytes reach `pickle.loads`, `yaml.load` without a safe loader, Java native deserialization, or an equivalent.

## Do not use this skill when

- The format is parsed into plain data only (JSON into dicts) with no object construction.
- The payload is XML — use `cwe-611-xxe`.

## When another skill also applies

- `cwe-611-xxe` also fires on untrusted XML, and the negative criterion above sends every XML payload there — right for a parser that resolves entities, wrong for one that instantiates the types the document names (`XMLDecoder`, XStream). **This skill wins** whenever the reader constructs objects the document chose, because that is the sink a gadget oracle drives; entity or DTD expansion with no object construction stays with `cwe-611-xxe`.

## Procedure

**Sink.** Deserializing untrusted bytes with a mechanism that can instantiate arbitrary types
or invoke callbacks: `pickle.loads`, `yaml.load` (unsafe loader), native Java
`ObjectInputStream.readObject`, `Marshal.load`.

**Source.** Untrusted serialized bytes (request body, file, cache, queue).

**Neutralized when.** A data-only format/loader is used (`yaml.safe_load`, JSON, schema-bound
parsers), or type allowlisting rejects unexpected classes.

## Oracle

Condition: **deserializing attacker bytes ran a callback the payload chose.** Use a benign
marker gadget defined in the probe itself, never a real-world gadget chain: for example a
pickle `__reduce__`, or a test-local Java class's `readObject`, whose only effect is creating
`/tmp/harness_canary_<nonce>`. Serialize it with the target's own mechanism. Map the result
onto `HARNESS_PROBE` (see `probe`):

- `target_reached`: the real deserialization entry point received the gadget bytes,
  including when a safe loader or type allowlist rejects them.
- `oracle_valid`: the gadget was serialized with the target's own mechanism and the canary did
  not exist before.
- `vulnerability_observed`: the canary exists after the target call and did not before.
- `positive_control`: the unsafe primitive called directly (`pickle.loads`,
  `ObjectInputStream.readObject`) on equivalent bytes creates a separate canary path.
- `negative_control`: benign serialized data of the expected shape passes through the
  target and no canary appears.
