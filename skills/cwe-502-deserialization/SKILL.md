---
name: cwe-502-deserialization
description: "Recognize unsafe deserialization sinks and define a safe, sandbox-only gadget oracle."
---

# CWE-502: Unsafe deserialization

**Sink.** Deserializing untrusted bytes with a mechanism that can instantiate arbitrary types
or invoke callbacks: `pickle.loads`, `yaml.load` (unsafe loader), native Java
`ObjectInputStream.readObject`, `Marshal.load`.

**Source.** Untrusted serialized bytes (request body, file, cache, queue).

**Neutralized when.** A data-only format/loader is used (`yaml.safe_load`, JSON, schema-bound
parsers), or type allowlisting rejects unexpected classes.

## Oracle

Prove that deserialization can trigger execution/instantiation defined by the payload, using a
**local, benign marker gadget that lives in the test itself** — do not import or craft
real-world exploitation gadget chains.

- Define, inside the test, a tiny class whose deserialization callback (e.g. `__reduce__` /
  `readResolve`) only creates `/tmp/harness_canary_<nonce>` or sets a flag the test then prints
  as the oracle marker.
- Serialize an instance with the same mechanism, then hand those bytes to the target callable.
- Print the precondition marker before the deserialize call; fire the oracle when the callback
  ran (canary present / flag set). A safe loader refuses or ignores the callback — a valid
  negative.

The gadget is a harness-local no-op marker; it demonstrates reachability of the callback path
without any real payload.
