---
name: cwe-208-observable-timing-discrepancy
description: Secret comparisons that leak through timing. Use this when the finding is CWE-208 or a secret is compared in non-constant time.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-208: Observable timing discrepancy

## Use this skill when

- The finding is classified CWE-208, or names a timing side channel in a secret comparison.
- A password, token, HMAC, API key or signature is compared with `==`, `eq`, `equals`,
  `strcmp` or an early-returning loop, so the time to reject depends on how many leading
  characters matched.

## Do not use this skill when

- The comparison already uses a constant-time primitive (`hmac.compare_digest`,
  `crypto.timingSafeEqual`, `MessageDigest.isEqual`) — then the finding is likely a false
  positive; say so.
- The weakness is unlimited attempts — use `cwe-307-improper-restriction-of-authentication-attempts`.
- The signature is not verified at all — use `cwe-347-improper-verification-of-signature`.

## When another skill also applies

- `cwe-347-improper-verification-of-signature` wins when the signature check is absent or
  forgeable; a timing leak only matters once the check otherwise works.
- `cwe-307-improper-restriction-of-authentication-attempts` compounds this: a timing oracle needs many attempts. Report the attempt limit
  through that skill.

## Procedure

**Sink.** The secret comparison that decides acceptance: `token == expected`,
`user_mac == computed_mac`, `password == stored`.

**Guard.** A constant-time comparison, or comparison of fixed-length hashes rather than the
secrets themselves (comparing HMACs of equal length with `==` still leaks, but less usefully;
treat full-length digest comparison with care).

**Source.** An attacker who can measure response time across many requests and control the
guessed value one position at a time.

**Neutralized when.** The comparison is constant-time over the secret, or no remote timing
signal is observable (the result is dominated by unrelated work), or attempts are strictly
limited.

## Oracle

Be conservative. Timing measurements inside a shared sandbox are noisy and not a reliable
oracle; a microbenchmark that "shows" a difference is weak evidence and a null result proves
nothing. Prefer a **structural** determination:

- `oracle_valid`: the check is whether the real comparison on the sink line is a plain
  byte-by-byte equality on the secret (`==`/`eq`/`equals`/`strcmp`/early-return loop) rather
  than a constant-time primitive, read from source.
- `target_reached`: the real verification function ran with a candidate value.
- `vulnerability_observed`: **only** `true` when the sink is a plain equality on the secret
  (not a constant-time call) and the comparison is reachable with attacker-controlled,
  attacker-measurable input. Otherwise `false`.
- `positive_control`: a probe-owned plain `==` comparison is confirmed to be the non-constant
  form (optionally demonstrated by early return on a mismatch position).
- `negative_control`: a constant-time primitive is confirmed to examine the full input.

Do not upgrade to `potentially_exploitable` from a timing microbenchmark alone. Treat a raw
timing measurement as supporting context, never as the oracle.

## Language notes

- **Python:** `token == expected` versus `hmac.compare_digest`.
- **JavaScript:** `a === b` or `Buffer.compare` early-exit versus `crypto.timingSafeEqual`
  (which also requires equal-length buffers).
- **Java:** `String.equals`/`Arrays.equals` versus `MessageDigest.isEqual`.
- **Perl:** `eq` / `cmp` versus a constant-time loop XOR-ing all bytes.

## Pitfalls

- Equal-length digests compared with `==` leak far less than variable-length secrets; scope the
  claim and often stay `inconclusive`.
- Remote exploitability needs a measurable signal over the network and many attempts; absent
  evidence of both, report `inconclusive` with the structural finding.
- Network jitter, the runtime JIT and GC all swamp per-comparison timing in this sandbox.

## Verdict guidance

- Usually `inconclusive`: name the non-constant comparison and that remote measurability and
  attempt volume are unestablished.
- `potentially_exploitable` only when the sink is a plain `==` on a secret, attacker-controlled
  and measurable, with attempts unlimited (cross-reference `cwe-307-improper-restriction-of-authentication-attempts`).
- `likely_not_exploitable`: cite the constant-time primitive on the sink line.
