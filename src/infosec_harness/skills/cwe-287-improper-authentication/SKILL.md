---
name: cwe-287-improper-authentication
description: Authentication checks that can be skipped or bypassed. Use this when the finding is CWE-287/306/620/640 or an action runs without proof of identity.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-287: Improper authentication (also CWE-306, CWE-620, CWE-640)

## Use this skill when

- The finding is classified CWE-287, CWE-306 (missing authentication for a critical function),
  CWE-620 (unverified password change) or CWE-640 (weak password recovery).
- A login, token or password check can return success without the caller proving the secret:
  a fall-through branch, an empty or `null` credential accepted, a type-confused comparison,
  a debug flag or header that marks the caller as authenticated.
- A state-changing handler (password change, recovery, admin action) is reachable with no
  authentication check at all.

## Do not use this skill when

- The caller is authenticated but acts on another principal's object — use
  `cwe-862-missing-authorization`.
- The accepted secret is a constant in source — use `cwe-798-hard-coded-credentials`.
- The token is a signed structure whose signature is not checked — use
  `cwe-347-improper-verification-of-signature`.
- The weakness is unlimited guessing — use `cwe-307-improper-restriction-of-authentication-attempts`.

## When another skill also applies

- `cwe-798-hard-coded-credentials` also fires when the bypass is a built-in password. **That
  skill wins**: its oracle (the constant is accepted by the real path) is narrower and decisive.
- `cwe-347-improper-verification-of-signature` wins for forged tokens: the authentication
  check exists but trusts unsigned claims.
- `cwe-384-session-fixation` wins when authentication works but the session identifier it
  binds to is attacker-chosen.

## Procedure

**Sink.** The protected operation that should require identity: returning a session or token,
changing a password or e-mail, resetting credentials, an admin function.

**Guard.** The code that decides the caller is authenticated: credential comparison, session
lookup, middleware or decorator, recovery-token check. Read every branch, including error and
default branches, and the order of middleware registration.

**Source.** Credentials, headers, cookies, recovery tokens and request fields the caller sends.

**Neutralized when.** Every path to the sink passes a guard that compares the presented
credential with the stored one and fails closed on missing, empty, malformed or wrong values;
password change re-verifies the current password (CWE-620); recovery tokens are random,
single-use, bound to the account and expiring (CWE-640).

## Oracle

Condition: **the protected operation succeeded for a caller who presented no valid
credential.** Drive the real entry point in process, or through a loopback server the probe
starts, with a probe-created account whose password is a nonce.

- `target_reached`: the real login, middleware or handler ran with the finding-shaped request
  (missing, empty, wrong or malformed credential), including when it rejects it.
- `oracle_valid`: success is read from the target's own return value or state for a
  probe-created account.
- `vulnerability_observed`: that request obtained the protected result (session issued,
  password changed, admin data returned) as observed through the target's own return value or
  state in the probe's store.
- `positive_control`: the correct nonce password through the same path succeeds, proving the
  oracle can see success.
- `negative_control`: a clearly wrong password is rejected, proving the oracle can see failure.
  If the wrong password also succeeds, the guard is absent for every input; say so.

## Language notes

- **Python:** `if user and user.password == pw` style checks; `hmac.compare_digest` raising
  on mixed types; Flask/Django decorators missing from one route; `request.headers.get("X-Admin")`.
- **JavaScript:** `==` coercion (`0 == ""`), assignment typos inside conditions, Express
  middleware registered after the route, `req.body.password` arriving as an array or object.
- **Java:** `equals` on `null`, Spring Security `permitAll` ordering, filters that `return`
  without `chain.doFilter` only on some branches.
- **Perl:** `eq` against `undef` under no warnings, `||` defaulting an empty password,
  `$ENV{REMOTE_USER}` trusted in a CGI not behind real authentication.

## Pitfalls

- An authentication framework being configured is not evidence it protects this route.
  Trace the route registration.
- A probe that seeds a session directly skips the guard under test.
- Recovery tokens: generation quality belongs to `cwe-330-insufficient-randomness`; this skill
  covers whether the token is checked, bound and expired.

## Verdict guidance

- `potentially_exploitable`: the finding-shaped request reached the sink without a valid
  credential while the controls behaved.
- `likely_not_exploitable`: cite the guard line that rejected the request, with the positive
  control showing the same path succeeds with the right credential.
- `inconclusive` when the guard lives in deployment configuration (reverse proxy, gateway)
  that the repository does not contain; name it.
