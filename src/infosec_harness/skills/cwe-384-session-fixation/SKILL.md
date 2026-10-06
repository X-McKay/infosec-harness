---
name: cwe-384-session-fixation
description: Session ids that survive login, never expire or lack protective cookie flags. Use this when the finding is CWE-384/613/614/1004.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-384: Session fixation (also CWE-613, CWE-614, CWE-1004)

## Use this skill when

- The finding is classified CWE-384 (session fixation), CWE-613 (insufficient session
  expiration), CWE-614 (sensitive cookie without `Secure`) or CWE-1004 (sensitive cookie
  without `HttpOnly`).
- Login, privilege elevation or logout keeps the same session identifier, or adopts one the
  client supplied.
- Sessions or remember-me tokens have no idle or absolute expiry, or logout does not
  invalidate them server-side.

## Do not use this skill when

- The identifier is predictable — use `cwe-330-insufficient-randomness`.
- Authentication itself can be skipped — use `cwe-287-improper-authentication`.
- The token is a signed structure accepted without verification — use
  `cwe-347-improper-verification-of-signature`.

## When another skill also applies

- `cwe-330-insufficient-randomness` also fires when a fixed-up session id is also guessable.
  **This skill wins** when the id is unchanged across login: no guessing is needed.
- `cwe-352-csrf` wins for whether a cross-site request changes state; cookie flags here are
  reported as attributes, not as a CSRF verdict.

## Procedure

**Sink.** Binding an authenticated identity to a session: `session[user] = ...`, writing the
store entry, issuing `Set-Cookie` after login.

**Guard.** Session regeneration on login (`session.regenerate`, `cycle_key`,
`changeSessionId`, a fresh id from a CSPRNG), rejection of unknown client-supplied ids,
server-side invalidation on logout, expiry checks, cookie attributes.

**Source.** A session id the attacker can plant before login (cookie, URL parameter), or a
stale id the attacker captured.

**Neutralized when.** Login issues a new id unrelated to the pre-login one and the old id no
longer authenticates; logout and expiry invalidate the id in the server store; session
cookies carry `HttpOnly`, `Secure` (for HTTPS deployments) and an appropriate `SameSite`.

## Oracle

Condition: **an identifier known to the attacker before login authenticates as the victim
after login** (CWE-384), or **an identifier that should be dead still authenticates**
(CWE-613). Drive the real session code in process or through a loopback server.

- `target_reached`: the real login ran with a pre-planted or pre-login session id, including
  when it rejects or replaces that id.
- `oracle_valid`: the pre-login id was planted before login and is presented unchanged
  afterwards.
- `vulnerability_observed`: after the victim logs in, a request presenting the pre-login id
  receives the victim's authenticated response, or the id equals the post-login id.
  For CWE-613: the id still authenticates after logout or after a fixed clock passes expiry.
- `positive_control`: the post-login id issued to the victim authenticates, proving the oracle
  sees an authenticated session.
- `negative_control`: a random id the server never issued does not authenticate.

For CWE-614/1004 the observation is the `Set-Cookie` header of the real response: record the
flags present. A missing flag is a configuration fact; exploitation needs a separate channel
(cleartext transport, XSS) that this probe does not establish. Prefer `inconclusive` unless
the finding scopes itself to the attribute.

## Language notes

- **Python:** Flask's signed cookie session cannot be fixed, but server-side stores
  (Flask-Session, Django) need `cycle_key()`/`login()`; hand-rolled dict stores keyed by a
  client cookie.
- **JavaScript:** `express-session` without `req.session.regenerate()` on login; custom
  `Map` stores that reuse `req.cookies.sid`.
- **Java:** `HttpServletRequest.changeSessionId()` or `invalidate()` missing; Spring Security
  `sessionFixation().none()`.
- **Perl:** `CGI::Session` loaded with the client's id and never renewed; Plack session
  middleware state.

## Pitfalls

- Inject a fixed clock or a short configured lifetime for expiry tests; never sleep for real
  session lifetimes.
- A new cookie value that maps to the same server-side record is still fixation.
- Read the regeneration call's semantics: some APIs copy data into a new id, others only
  rename the cookie.

## Verdict guidance

- `potentially_exploitable`: the attacker-known id authenticated as the victim through the
  real handlers.
- `likely_not_exploitable`: cite the regeneration or invalidation line, with the positive
  control showing the new id works.
- `inconclusive` for cookie-flag-only findings without a demonstrated exposure channel.
