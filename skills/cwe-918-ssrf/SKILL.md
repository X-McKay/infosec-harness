---
name: cwe-918-ssrf
description: "Recognize SSRF sinks and define a loopback oracle that needs no external network."
---

# CWE-918: Server-side request forgery (SSRF)

**Sink.** Issuing a network request to a URL/host built from untrusted input: HTTP client
calls, URL openers, webhook/callback fetchers.

**Source.** Untrusted URLs, hostnames, or components thereof.

**Neutralized when.** The target is allowlisted, or the resolved address is validated against
private/loopback/link-local ranges before the request.

## Oracle

Probes run with **no external network**, which fits SSRF triage: the exploit condition is
**"the code would issue a request to an attacker-chosen destination."** Observe intent, not a
real fetch:

- Preferred: pass input naming a destination and capture the request the code *attempts* via a
  fake/stub HTTP client or transport injected into the target. Fire the oracle when the
  captured destination is the attacker-chosen one (i.e. no allowlist/SSRF guard rejected it).
  Unlike most weaknesses this one cannot use the real sink — the sandbox has no egress — so
  the substitution is deliberate. It is only sound if the target genuinely uses the client you
  injected: verify that from the code before relying on it. A transport the code never picked
  up produces a silent false negative that looks exactly like a clean one, so if you cannot
  confirm the injection point, use the loopback listener below instead.
- If the code binds its own client, point the input at a loopback listener the test starts
  inside the sandbox that responds with `HARNESS_ORACLE::<nonce>`; fire the oracle when the
  code returns/threads that response through. A guard that blocks loopback/private targets
  yields a valid negative.

Never rely on reaching a real external host; the sandbox has no egress.
