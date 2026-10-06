---
name: cwe-79-xss
description: Untrusted input reaching HTML markup unencoded (reflected or stored XSS). Use this when the finding is CWE-79.
metadata:
  owner: appsec
  version: 2.0.1
---

# CWE-79: Cross-site scripting

## Use this skill when

- The finding is classified CWE-79, or names XSS or cross-site scripting.
- A caller-supplied value is concatenated into HTML, an attribute, or inline script.
- A template's auto-escaping is bypassed (`| safe`, `Markup`, `dangerouslySetInnerHTML`).

## Do not use this skill when

- The value is rendered as text by a framework that escapes by default and the code did not opt out.
- The sink is a SQL query or a shell command, not markup.

## Procedure

**Sink.** Untrusted input placed into an HTML/JS response or DOM without context-appropriate
encoding: template interpolation marked "safe"/`| safe`, `innerHTML = x`, string-built HTML,
`Markup(x)`.

**Source.** Untrusted values rendered into a page.

**Neutralized when.** The value is HTML/attribute/JS-encoded for its context, or the framework
auto-escapes and the code did not opt out.

## Oracle

Condition: **a markup-significant payload survived into the output unencoded.** Test the real
rendering function or template, not a browser; no DOM or script execution is needed. Use a
nonce token such as `<b id="h<nonce>">` (or `"><b id="h<nonce>">` inside an attribute). Map
the result onto `HARNESS_PROBE` (see `probe`):

- `target_reached`: the real renderer ran with the token in the attacker-controlled field and
  returned output or raised its own validation error.
- `oracle_valid`: the token's raw and entity-encoded forms are distinguishable in the output.
- `vulnerability_observed`: the output contains the token in markup-significant form (raw
  `<`, or an unescaped attribute break) rather than entity-encoded (`&lt;`, `&quot;`).
- `positive_control`: the check fires on a string with the raw token concatenated into markup.
- `negative_control`: plain text `h<nonce>` in the same field appears in the output, proving
  the field is rendered, and the check stays silent; it also stays silent on `html.escape(token)`.
