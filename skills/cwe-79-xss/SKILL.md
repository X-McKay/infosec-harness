---
name: cwe-79-xss
description: "Recognize reflected/stored XSS sources, sinks, and encoders, and define a deterministic output oracle."
---

# CWE-79: Cross-site scripting

**Sink.** Untrusted input placed into an HTML/JS response or DOM without context-appropriate
encoding: template interpolation marked "safe"/`| safe`, `innerHTML = x`, string-built HTML,
`Markup(x)`.

**Source.** Untrusted values rendered into a page.

**Neutralized when.** The value is HTML/attribute/JS-encoded for its context, or the framework
auto-escapes and the code did not opt out.

## Oracle

This is a unit-level triage, so test the **rendering function**, not a browser. The exploit
condition is **"a markup-significant payload survived into the output unencoded."**

- Feed the target renderer input containing a unique, markup-significant token derived from the
  nonce (e.g. wrapped in angle brackets so an unencoded copy would form an element/attribute).
- Inspect the returned string. Fire the oracle when the token appears in a markup-significant
  form (raw `<...>` or an unescaped attribute break) rather than entity-encoded.
- If the output shows the token encoded (`&lt;...&gt;` etc.), that is a valid negative.

No DOM or script execution is needed or wanted; the oracle is a string-encoding check.
