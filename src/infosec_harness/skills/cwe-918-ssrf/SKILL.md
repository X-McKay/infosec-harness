---
name: cwe-918-ssrf
description: Recognize SSRF sinks and define a loopback oracle that needs no external network. Use
  this when the finding is CWE-918 or untrusted input chooses a request destination.
metadata:
  owner: appsec
  version: 2.0.0
---

# CWE-918: Server-side request forgery (SSRF)

## Use this skill when

- The finding is classified CWE-918, or names SSRF or server-side request forgery.
- A caller-supplied value becomes part of a URL, host, or port the server then requests.

## Do not use this skill when

- The destination is fixed and only the request body is untrusted.
- The value is used as a filesystem path — use `cwe-22-path-traversal`.

## When another skill also applies

- `cwe-22-path-traversal` also fires when the caller-chosen destination resolves under a scheme such as `file:` that reaches the filesystem, and each skill redirects to the other. **This skill wins** while a URL resolver stands between the value and the file: the fetcher is the sink and destination validation is the guard under test. Use `cwe-22-path-traversal` when the value is joined onto a base directory and opened with no resolver in between.
- Use `probe` for source integrity, controls and evidence requirements. A substituted HTTP transport can explain intent but does not establish actual network behavior.

## Procedure

**Sink.** Issuing a network request to a URL/host built from untrusted input: HTTP client
calls, URL openers, webhook/callback fetchers.

**Source.** Untrusted URLs, hostnames, or components thereof.

**Neutralized when.** The target is allowlisted, or the resolved address is validated against
private/loopback/link-local ranges before the request.

## Oracle

Condition: **the target sent a request to a destination the attacker chose.** Probes have no
external network. Start a loopback HTTP listener on `127.0.0.1` with an ephemeral port inside
the probe; it records requests and serves a unique marker. Exercise the original callable and
its real HTTP client. Map the result onto `HARNESS_PROBE` (see `probe`):

- `target_reached`: the real callable ran with an attacker-selected listener URL, including
  when its destination validation rejects it. An exception alone is not a block: decide
  whether the guard or a setup failure raised it.
- `vulnerability_observed`: the listener recorded the target's request, or the target
  returned the listener's marker.
- `positive_control`: a direct request from the probe to the listener is recorded.
- `negative_control`: a benign destination that is not the listener leaves no recorded request.

A loopback rejection only establishes that tested boundary. It does not prove that all
redirects, alternate encodings, DNS changes or other destinations are safe. Trace those
conditions in the source and scope the conclusion accordingly. If the sandbox cannot
support the required observation, report the limitation. A fake transport can diagnose
which URL the target attempted, but cannot substitute for an execution claim.
