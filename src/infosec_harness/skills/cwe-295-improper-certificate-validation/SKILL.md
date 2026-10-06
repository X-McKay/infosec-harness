---
name: cwe-295-improper-certificate-validation
description: Recognize TLS clients that skip or weaken certificate and hostname verification, and define a loopback TLS oracle with a probe-generated self-signed certificate.
  Use this when the finding is CWE-295 or a client disables verification.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-295: Improper certificate validation

## Use this skill when

- The finding is classified CWE-295, or names disabled, skipped or custom certificate or
  hostname verification.
- A TLS client sets `verify=False`, an all-trusting `SSLContext`, `rejectUnauthorized: false`,
  `TrustManager` that accepts everything, a hostname verifier that returns true, or
  `curl -k` / `IO::Socket::SSL` with `SSL_verify_mode => 0`.

## Do not use this skill when

- The connection is plain HTTP with no TLS at all — use `cwe-319-cleartext-transmission`.
- The private key or CA is hard-coded — use `cwe-798-hard-coded-credentials`.
- A JWT or message signature is unverified — use `cwe-347-improper-verification-of-signature`.

## When another skill also applies

- `cwe-319-cleartext-transmission` also fires when the fallback on a TLS error is to retry
  over plaintext. **This skill wins** while a TLS handshake happens and the defect is accepting
  a bad certificate; that skill wins once traffic leaves unencrypted.

## Procedure

**Sink.** The TLS client call that establishes the connection and should validate the peer:
`requests.get(..., verify=...)`, `ssl.create_default_context` or a custom context, `https.get`
with an agent, `HttpsURLConnection` with a custom `SSLSocketFactory`, `LWP`/`IO::Socket::SSL`.

**Guard.** Verification left enabled: default contexts, `check_hostname=True`,
`CERT_REQUIRED`, a real trust store, a hostname verifier that compares the CN/SAN.

**Source.** A man-in-the-middle who presents a certificate the real CA chain would reject.

**Neutralized when.** The client verifies the chain against a trust store and checks the
hostname, and no option downgrades that.

## Oracle

Condition: **the client completed a TLS session to a server whose certificate a correct
client would reject.** Inside the probe, generate a self-signed certificate for `localhost`
(for example with the `cryptography` library, or `openssl` if available, written under
`/workspace/repo`), start a loopback HTTPS server on `127.0.0.1` with it serving a nonce, and
point the real client at it. Everything stays on loopback; no external host is contacted.

- `target_reached`: the real client function ran against the loopback HTTPS URL, including
  when it raises a verification error.
- `vulnerability_observed`: the client returned the server's nonce, meaning it accepted the
  untrusted self-signed certificate.
- `positive_control`: a deliberately non-verifying client (the probe's own, with verification
  off) reaches the server and gets the nonce, proving the server and nonce work.
- `negative_control`: a correctly verifying client against the same server fails the
  handshake, proving the certificate is genuinely untrusted.

A hostname-mismatch variant uses a certificate whose SAN is a different name than the one the
client connects to; the oracle is the same (connection succeeds despite the mismatch).

## Language notes

- **Python:** `verify=False` in requests/httpx; `ssl._create_unverified_context`;
  `context.check_hostname=False` with `CERT_NONE`.
- **JavaScript:** `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, a custom
  `checkServerIdentity` returning undefined.
- **Java:** a `TrustManager` whose `checkServerTrusted` is empty; `setHostnameVerifier`
  returning true; `SSLContext.getInstance("TLS")` initialised with such a manager.
- **Perl:** `IO::Socket::SSL` `SSL_verify_mode => SSL_VERIFY_NONE`; `LWP::UserAgent`
  `ssl_opts(verify_hostname => 0)`.

## Pitfalls

- Generate the certificate at run time under `/workspace/repo`; never ship a key as original
  source and never target a real host.
- A client that fails on the self-signed cert but has `verify` wired to a config flag may still
  be vulnerable when the flag is set; report the condition.
- Remove any temporary key/cert files the probe created in a `finally` block; they must be
  regular files, not links.

## Verdict guidance

- `potentially_exploitable`: the real client accepted the untrusted certificate, with both
  controls behaving.
- `likely_not_exploitable`: the real client rejected it while the positive control succeeded;
  cite the verification setting.
- `inconclusive` when TLS libraries needed for the probe are unavailable; name them.
