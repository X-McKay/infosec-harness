---
name: cwe-319-cleartext-transmission
description: Secrets or credentials sent or stored without encryption. Use this when the finding is CWE-319/311/312/313.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-319: Cleartext transmission of sensitive information (also CWE-311, CWE-312, CWE-313)

## Use this skill when

- The finding is classified CWE-319, CWE-311 (missing encryption), CWE-312 (cleartext storage)
  or CWE-313 (cleartext storage in a file).
- Credentials, tokens, personal data or secrets are sent over `http://`, plain TCP, SMTP
  without STARTTLS, or written to a log or file in cleartext.

## Do not use this skill when

- TLS is used but the certificate is not validated — use
  `cwe-295-improper-certificate-validation`.
- The secret is a literal in source — use `cwe-798-hard-coded-credentials`.
- The data is hashed weakly rather than sent in clear — use `cwe-327-broken-crypto`.

## When another skill also applies

- `cwe-295-improper-certificate-validation` covers accepting a bad certificate on a TLS link.
  **This skill wins** when there is no encryption on the wire at all, or when a TLS failure
  falls back to plaintext.

## Procedure

**Sink.** The transmission or storage call: an HTTP (not HTTPS) client request carrying the
secret, a socket write, an e-mail send, a log or file write.

**Guard.** TLS on the channel (`https`, STARTTLS, a wrapped socket), or encryption of the
payload before it leaves, or redaction before logging.

**Source.** A network observer on the path, or anyone who can read the log or file.

**Neutralized when.** The channel is encrypted (verified TLS) for every send of the secret, or
the secret is encrypted or redacted before transmission or storage.

## Oracle

Condition: **the secret appeared in the clear in the captured channel or stored file.** Start
a loopback listener on `127.0.0.1` (a plain `socketserver`/`http.server`, or a plain TCP
socket) that records exactly the bytes it receives, and point the real client at it with a
nonce secret. For storage findings, run the real write and read the resulting file bytes. All
observation is on loopback or sandbox files.

- `target_reached`: the real send or write function ran with the nonce secret.
- `oracle_valid`: the listener or file read records the exact bytes the target sent or stored.
- `vulnerability_observed`: the nonce appears verbatim in the captured bytes or the stored
  file.
- `positive_control`: the probe sends the nonce over the same plain channel directly and the
  listener records it, proving capture works.
- `negative_control`: a send of inert, non-secret bytes leaves the nonce absent from the
  capture.

If the code uses `https`, do not disable TLS to force a capture; that would test a different
program. Observe whether the real path is plaintext; if it is TLS, this is likely a CWE-295
question instead.

## Language notes

- **Python:** `urllib`/`requests` with `http://`; `smtplib.SMTP` without `starttls`;
  `logging` of a password; writing a token to a file with `open`.
- **JavaScript:** `http.request` to an `http://` URL; `console.log(password)`; writing secrets
  with `fs.writeFile`.
- **Java:** `URL("http://...")`; `Socket` without `SSLSocket`; logging credentials via
  `logger.info`.
- **Perl:** `LWP` to `http://`; `IO::Socket::INET` (not `::SSL`); `print $log $password`.

## Pitfalls

- The scheme may be built from a variable; trace what it resolves to on the real path.
- Base64 or URL-encoding is not encryption; decode in the probe and compare the nonce.
- For logs, check the real logging configuration, not just the call site.

## Verdict guidance

- `potentially_exploitable`: the nonce was captured in cleartext from the real send or write.
- `likely_not_exploitable`: cite the TLS or encryption step on the path, with the positive
  control capturing a direct plaintext send.
- `inconclusive` when the channel's encryption depends on deployment configuration absent from
  the repository.
