---
name: cwe-798-hard-coded-credentials
description: Recognize credentials and keys embedded in source or stored recoverably, and distinguish one the authentication path accepts from a string that only looks like one.
  Use this when the finding is CWE-798, CWE-259, CWE-321 or CWE-522, or a secret literal appears near a login or key use.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-798: Hard-coded credentials (also CWE-259, CWE-321, CWE-522)

## Use this skill when

- The finding is classified CWE-798, CWE-259 (hard-coded password), CWE-321 (hard-coded
  cryptographic key) or CWE-522 (insufficiently protected credentials).
- A password, API key, signing key or encryption key is a literal in source, a default in
  code, or a fallback when configuration is missing.
- Credentials are stored or transmitted in a recoverable form (plaintext, reversible
  encoding) where a one-way or protected form is expected (CWE-522).

## Do not use this skill when

- The literal is a test fixture, example or placeholder that no production path reads.
  Establish that through reachability and report it as the blocking condition.
- The password is hashed with a weak algorithm — use `cwe-327-broken-crypto`.
- Credentials are sent in cleartext over a network — use `cwe-319-cleartext-transmission`.

## When another skill also applies

- `cwe-287-improper-authentication` also fires for a built-in bypass password. **This skill
  wins**: the oracle is that the literal itself is accepted.
- `cwe-347-improper-verification-of-signature` also fires when a hard-coded HMAC key signs
  tokens. **This skill wins** when the key is the finding; that skill wins when verification is
  skipped regardless of the key.

## Procedure

**Sink.** The authentication or cryptographic use of the literal: the comparison in the login
path, the key passed to HMAC, cipher or JWT signing, the outbound client's credential.

**Guard.** Whether the literal is actually used: configuration lookup that overrides it,
environment variable required at startup (fail closed when absent), a feature flag that
disables the path, a hash that the literal does not match.

**Source.** The attacker knows the literal because the source, binary or package is
readable by them. That is the precondition; state it.

**Neutralized when.** The authentication path reads credentials only from configuration or a
secret store and fails closed when they are absent; any literal is unused, overridden on
every path, or only a placeholder that the real path rejects.

## Oracle

Condition: **the literal from source is accepted by the real authentication or key path.**
A string that looks like a password is not evidence; acceptance is.

- `target_reached`: the real login, verifier or decryptor ran with the literal as the
  credential or key, including when it rejects it.
- `vulnerability_observed`: the literal authenticated (session or success returned), or a
  token signed or ciphertext produced with the literal is accepted or decrypted by the target.
- `positive_control`: a credential the probe provisions through the target's real
  configuration route authenticates, proving the oracle sees success.
- `negative_control`: a random nonce credential is rejected.

For CWE-522, the oracle is that the stored or logged form of a probe-created password
reveals the password: decode it with the reversible scheme found in source and compare.
Configure any required environment or file with probe-chosen values that differ from the
literal, so a literal accepted anyway is distinguishable from configuration.

## Language notes

- **Python:** `if password == "admin123"`, `os.environ.get("KEY", "dev-secret")` fallbacks,
  `SECRET_KEY` literals in settings modules.
- **JavaScript:** `process.env.JWT_SECRET || "changeme"`, literals in `config/default.json`
  that ship to production.
- **Java:** `static final String PASSWORD`, keystore passwords in code, `SecretKeySpec` on a
  literal byte array.
- **Perl:** `my $ADMIN_PASS = '...'`, `eq` comparison in a login sub, `%CONFIG` defaults.

## Pitfalls

- Never use real credentials found in the repository against anything outside the
  sandbox. The oracle exercises only the target's own code with its own literal.
- Do not print the literal at length in probe output; a short prefix and a boolean suffice.
- An env-var fallback is only reachable when the variable is unset; state which deployment
  condition the verdict needs.

## Verdict guidance

- `potentially_exploitable`: the literal was accepted by the real path under the deployment
  condition you state.
- `likely_not_exploitable`: cite the line where configuration replaces the literal or where
  the path fails closed, with the positive control passing.
- `inconclusive` when acceptance depends on deployment configuration absent from the repository.
