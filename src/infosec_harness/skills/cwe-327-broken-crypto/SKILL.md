---
name: cwe-327-broken-crypto
description: Weak cryptographic algorithms, modes, key sizes or unsalted password hashing. Use this when the finding is CWE-327/328/326/916/759/760.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-327: Broken or risky cryptographic algorithm (also CWE-328, CWE-326, CWE-916, CWE-759, CWE-760)

## Use this skill when

- The finding is classified CWE-327 (broken algorithm), CWE-328 (weak hash), CWE-326
  (inadequate key strength), CWE-916 (password hash with insufficient effort), CWE-759 (hash
  without salt) or CWE-760 (hash with predictable salt).
- Passwords are stored with MD5, SHA-1 or a single round of any fast hash, with no salt or a
  constant salt.
- Data is encrypted with DES, 3DES, RC4, ECB mode, a static IV, or RSA/DH keys below 2048 bits.

## Do not use this skill when

- The key or salt is a literal and the literal is the finding — use
  `cwe-798-hard-coded-credentials`.
- The randomness of keys, IVs or tokens is the issue — use `cwe-330-insufficient-randomness`.
- A signature or MAC is not verified — use `cwe-347-improper-verification-of-signature`.
- The hash is used for a non-security purpose (cache key, ETag, deduplication) and nothing
  relies on collision or preimage resistance. Say so and cite the use.

## When another skill also applies

- `cwe-330-insufficient-randomness` also fires for a predictable IV or salt. **This skill
  wins** when the salt is constant or absent (identical inputs give identical outputs);
  that skill wins when values vary but are predictable.
- `cwe-208-observable-timing-discrepancy` covers how hashes are compared; this skill covers
  which algorithm produced them.

## Procedure

**Sink.** The cryptographic call: `hashlib.md5(password)`, `MessageDigest.getInstance("MD5")`,
`createHash('sha1')`, `Cipher.getInstance("AES")` (defaults to ECB in Java), `Digest::MD5`.

**Guard.** The surrounding construction: a per-user random salt stored with the hash, a slow
KDF (`pbkdf2_hmac`, `scrypt`, bcrypt, Argon2) with a work factor, an authenticated mode
(GCM, ChaCha20-Poly1305) with a unique nonce, an adequate key size.

**Source.** The password or plaintext the application processes; an attacker who obtains the
stored hashes or ciphertexts.

**Neutralized when.** Passwords go through a slow, salted KDF with a work factor appropriate
to the algorithm; encryption uses an authenticated mode with unique nonces and adequate keys;
or the weak primitive has no security role.

## Oracle

Condition: **the stored or emitted value reveals the weak construction.** Call the real
storage or encryption function with probe-chosen inputs and inspect its output; do not
reimplement the target's function and test your copy.

- Unsalted or constant-salt hashing: two accounts with the same nonce password produce
  identical stored values, and the value equals `md5(password)` or `sha1(password)` computed
  independently in the probe.
- ECB mode: a plaintext of two identical 16-byte blocks produces two identical ciphertext
  blocks.
- Static IV or nonce: encrypting the same plaintext twice yields identical ciphertext.
- Key size: read the generated key's length from the real object.

Map the result onto `HARNESS_PROBE`:

- `target_reached`: the real hash, store or encrypt function ran with the probe's input.
- `oracle_valid`: the check inspects the real function's output for the specific weak
  construction, not a reimplementation.
- `vulnerability_observed`: the real output matched the weak construction above.
- `positive_control`: the probe's own weak construction (for example `hashlib.md5`, or AES
  in ECB) shows the pattern, proving the detector works.
- `negative_control`: the probe's own strong construction (salted `pbkdf2_hmac`, a random
  IV) does not show the pattern.

## Language notes

- **Python:** `hashlib.md5/sha1/sha256(pw)` with no salt; `hashlib.pbkdf2_hmac`,
  `hashlib.scrypt`, `bcrypt`; `cryptography` `modes.ECB`.
- **JavaScript:** `crypto.createHash('md5')`; `crypto.pbkdf2Sync`, `crypto.scryptSync`;
  `createCipheriv('aes-128-ecb')`; deprecated `createCipher`.
- **Java:** `MessageDigest`, `Cipher.getInstance("AES")` meaning ECB, `KeyPairGenerator`
  initialised with 1024; `PBKDF2WithHmacSHA256` iteration count.
- **Perl:** `Digest::MD5::md5_hex`, `Digest::SHA::sha1_hex`, `crypt` with a fixed two-char
  salt; `Crypt::*` modules may be absent in the sandbox.

## Pitfalls

- A strong algorithm with a constant salt is still CWE-760: test two accounts.
- Iteration counts matter for PBKDF2; cite the number and the reference you compare against.
- Do not crack or brute-force anything. The oracle compares against a value the probe computes
  from its own nonce password.

## Verdict guidance

- `potentially_exploitable`: the real output matched the weak construction and the value is
  security-relevant (stored password, confidential data); name the attacker precondition
  (database read, ciphertext access).
- `likely_not_exploitable`: cite the KDF, salt or mode line, with the controls passing.
- `inconclusive` when the algorithm is chosen by configuration absent from the repository.
