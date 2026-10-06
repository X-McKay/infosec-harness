---
name: cwe-352-csrf
description: Recognize state-changing requests that accept ambient credentials without an anti-forgery check, and define a cross-origin request oracle.
  Use this when the finding is CWE-352 or a cookie-authenticated handler changes state without a token or origin check.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-352: Cross-site request forgery (CSRF)

## Use this skill when

- The finding is classified CWE-352, or names CSRF or XSRF.
- A handler that changes state (transfer, e-mail change, settings, delete) authenticates the
  caller through credentials the browser attaches automatically: cookies, HTTP Basic, client
  certificates.
- The handler accepts the request without a synchronizer token, double-submit token, or
  `Origin`/`Referer` check, or accepts the change on `GET`.

## Do not use this skill when

- The request authenticates with a header the browser never adds by itself (an
  `Authorization: Bearer` token set by script) and no cookie fallback exists.
- The handler is read-only and the finding is about data exposure — use
  `cwe-862-missing-authorization`.
- The forged request needs script in the target origin — use `cwe-79-xss`.

## When another skill also applies

- `cwe-79-xss` also fires when an injected script submits the form: same-origin script reads
  any token, so CSRF defences do not apply. **That skill wins**.
- `cwe-384-session-fixation` covers the cookie attributes (`SameSite`, `Secure`,
  `HttpOnly`). **This skill wins** for whether a cross-site request changes state; cite a
  `SameSite=Strict` or `Lax` session cookie as a partial guard, never as the only reason.

## Procedure

**Sink.** The state change performed by the handler: the write to the store, the transfer, the
password or e-mail update.

**Guard.** Token verification (framework CSRF middleware, a per-session token compared in
constant time), `Origin`/`Referer` validation, a custom header requirement, `SameSite`
cookies. Check that the middleware is registered for this route and method and not exempted.

**Source.** The forged request: method, form body, and the victim's ambient cookie.

**Neutralized when.** A state change requires a value an attacker origin cannot read or set
(session-bound token, custom header with CORS preflight), or the handler rejects requests whose
`Origin` is not the application's own, and no `GET` path performs the change.

## Oracle

Condition: **a request carrying only the victim's ambient session and attacker-chosen
fields, with no token and a foreign `Origin`, changed the victim's state.** Run the real
application in process or on a loopback port. Log the victim in through the real login to
obtain the session cookie, as a browser would hold it.

- `target_reached`: the real handler (with its middleware chain) received the forged request,
  including when it answers 403.
- `vulnerability_observed`: the victim's state in the probe's store changed to the
  attacker's nonce value.
- `positive_control`: the same change submitted the legitimate way (with the token the
  application issues, or from its own origin) changes state, proving the oracle sees a change.
- `negative_control`: the forged request without the session cookie changes nothing.

Do not model the browser's `SameSite` enforcement inside the probe; report the cookie
attribute from the `Set-Cookie` header separately and scope the conclusion to it.

## Language notes

- **Python:** Django `@csrf_exempt`, `CSRF_COOKIE` settings; Flask-WTF `CSRFProtect` not
  initialised; `http.server` handlers with no token at all.
- **JavaScript:** Express with `cookie-session` or `express-session` and no `csurf`/`csrf-csrf`
  equivalent; `app.all` or `app.get` routes that mutate.
- **Java:** Spring Security `csrf().disable()`, `ignoringRequestMatchers`.
- **Perl:** Mojolicious `csrf_token` never validated; CGI forms without a hidden token.

## Pitfalls

- A token that is generated but never compared, or compared only when present, is no guard.
  Send the forged request with the token field omitted, not just wrong.
- JSON endpoints are still forgeable when they accept `text/plain` or form encodings.
- `SameSite=Lax` still allows top-level `GET` navigation; a mutating `GET` stays vulnerable.

## Verdict guidance

- `potentially_exploitable`: the forged request changed the victim's state through the real
  middleware chain.
- `likely_not_exploitable`: cite the token or origin check that rejected it, with the
  positive control changing state.
- `inconclusive` when protection depends on a proxy or browser behaviour the repository does
  not define; name it.
