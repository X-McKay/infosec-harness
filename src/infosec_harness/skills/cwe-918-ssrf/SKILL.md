---
name: cwe-918-ssrf
description: Untrusted input choosing a server-side request destination. Use this when the finding is CWE-918 or SSRF.
metadata:
  owner: appsec
  version: 2.0.1
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
- `oracle_valid`: the listener is on loopback and the target's real HTTP client, not a patched
  transport, sends the request.
- `vulnerability_observed`: the listener recorded the target's request, or the target
  returned the listener's marker.
- `positive_control`: a direct request from the probe to the listener is recorded.
- `negative_control`: a benign destination that is not the listener leaves no recorded request.

A loopback rejection only establishes that tested boundary. It does not prove that all
redirects, alternate encodings, DNS changes or other destinations are safe. Trace those
conditions in the source and scope the conclusion accordingly. If the sandbox cannot
support the required observation, report the limitation. A fake transport can diagnose
which URL the target attempted, but cannot substitute for an execution claim.

Patching the resolver (`socket.getaddrinfo`), the HTTP transport or the URL parser inside the
probe replaces the sink's real behaviour: it is a stand-in and can support the positive control
only, never `vulnerability_observed`. A threat model that needs the attacker to control the
allowlisted hosts themselves (their DNS, certificates or servers) is outside the finding's scope
unless the finding states it; record it as a limitation in the summary, not as exploitability.
