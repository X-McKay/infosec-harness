---
name: cwe-347-improper-verification-of-signature
description: Recognize tokens and messages whose signature is skipped, trusted by type, or verifiable with an attacker-known key, and define a forgery oracle.
  Use this when the finding is CWE-347 or a JWT or signed payload is accepted without sound verification.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-347: Improper verification of cryptographic signature

## Use this skill when

- The finding is classified CWE-347, or names a missing, optional or confused signature check.
- A JWT is decoded without verification, accepted with `alg: none`, or verified with an
  algorithm the attacker chooses (HS256 verified with an RS256 public key as the HMAC secret —
  key confusion).
- A signed message, webhook or license is parsed and trusted before (or without) its signature
  is checked, or the signature is compared non-constant-time against an attacker-known key.

## Do not use this skill when

- The signing key is a literal and that is the finding — use `cwe-798-hard-coded-credentials`.
- No signature or token is involved and identity is simply unchecked — use
  `cwe-287-improper-authentication`.
- A TLS peer certificate is unvalidated — use `cwe-295-improper-certificate-validation`.

## When another skill also applies

- `cwe-287-improper-authentication` also fires because a forged token is an authentication
  bypass. **This skill wins**: the oracle is a forged token the application accepts, which is
  more specific than "identity not proven".
- `cwe-798-hard-coded-credentials` wins when the key itself is the finding; this skill wins
  when verification is skipped or confused regardless of the key.

## Procedure

**Sink.** The decision that trusts the signed payload's claims: using the `sub`/`role` of a
JWT, acting on a webhook body, honouring a license.

**Guard.** Verification before use with a fixed expected algorithm and the correct key:
`jwt.decode(..., algorithms=["HS256"], key=...)`, `verify=True`, an HMAC compared with a
constant-time function, `alg: none` rejected.

**Source.** A token or message the attacker crafts, including its header and claimed algorithm.

**Neutralized when.** The verifier rejects `alg: none`, pins the expected algorithm so an
attacker cannot swap HS256 for RS256, verifies with the right key, and uses claims only after a
successful verification.

## Oracle

Condition: **a token the attacker forged, without the server's signing secret, was accepted by
the real verifier.** Build the forged token inside the probe using only attacker knowledge
(public inputs), then pass it to the real verification path.

- **`alg: none`:** craft a token with header `{"alg":"none"}` and the attacker's claims, empty
  signature; pass it to the real verifier.
- **Key confusion:** sign the attacker's claims with HS256 using the server's RS256 *public*
  key (a value the attacker has) as the HMAC secret, then present it.
- **Unverified decode:** present any token with attacker claims and a garbage signature.

Map the result onto `HARNESS_PROBE`:

- `target_reached`: the real verifier ran on the forged token, including when it rejects it.
- `vulnerability_observed`: the target accepted the forged token and exposed its attacker-chosen
  claim (for example `role=admin`).
- `positive_control`: a genuinely signed token (with the real secret the probe provisions for
  its own test server) is accepted, proving the oracle sees acceptance.
- `negative_control`: a token with a tampered claim but the real algorithm and a wrong secret
  is rejected, proving the verifier can reject.

## Language notes

- **Python:** `jwt.decode(token, options={"verify_signature": False})`, `algorithms` omitted
  so `none` or caller-chosen algorithms slip through; hand-rolled HMAC with `==` comparison.
- **JavaScript:** `jsonwebtoken` `jwt.decode` instead of `verify`; `algorithms` not pinned so
  `none`/HS256 confusion works; `verify` with the public key as a string secret.
- **Java:** `parseClaimsJwt` (unsigned) versus `parseClaimsJws`; `jjwt` without
  `requireSignature`; accepting the token's own `alg`.
- **Perl:** `Crypt::JWT::decode_jwt` with `verify_signature => 0` or no `accepted_alg`; manual
  base64 decode trusting the payload.

## Pitfalls

- Match the forgery to the sink's parser: some libraries reject `none` by default, so read the
  version and options rather than assuming.
- Key confusion needs the server's public key; if the repository does not expose one, note the
  precondition.
- Build the forged token with a JSON/base64 encoder in the probe; do not patch the verifier.

## Verdict guidance

- `potentially_exploitable`: the real verifier accepted a token forged without the secret.
- `likely_not_exploitable`: cite the algorithm pin and verification call, with the positive
  control accepting a genuine token and the negative control rejecting a tampered one.
- `inconclusive` when key confusion needs a public key the repository does not provide; say so.
