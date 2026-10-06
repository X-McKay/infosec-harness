---
name: cwe-1021-clickjacking
description: Pages that can be framed without X-Frame-Options or CSP frame-ancestors. Use this when the finding is CWE-1021, clickjacking or UI redressing.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-1021: Improper restriction of rendered UI layers (clickjacking)

## Use this skill when

- The finding is classified CWE-1021, or names clickjacking, UI redressing or missing
  `X-Frame-Options` / `Content-Security-Policy: frame-ancestors`.
- A page that performs an action on one click (confirm, delete, transfer, grant) is served
  without frame protection.

## Do not use this skill when

- The page is public, static and has no authenticated action; framing it gains nothing.
- The concern is reading cross-origin responses — use `cwe-942-permissive-cors`.

## When another skill also applies

- `cwe-16-security-misconfiguration` routes here; **this skill wins** for frame protections.
- Any injection skill (`cwe-79-xss`) **wins** if the same page also renders attacker markup:
  that is a stronger finding with its own oracle.

## Procedure

**Sink.** The HTML response of a sensitive page: its headers, and any `<meta>` that tries to
set them (meta tags cannot set `X-Frame-Options` or `frame-ancestors`).

**Guard.** `X-Frame-Options: DENY` or `SAMEORIGIN`; `Content-Security-Policy` with
`frame-ancestors 'none'` or `'self'`; framework middleware that adds either (Django
`XFrameOptionsMiddleware`, `helmet.frameguard`, Spring Security `frameOptions()`); a
reverse-proxy rule in the repository's deployment configuration.

**Neutralized when.** Every response for the sensitive route carries one of the headers with
a restrictive value, or the action requires a second step that framing cannot complete
(re-authentication, typed confirmation).

**Source.** A hostile page that frames the target; there is no attacker-controlled input to
the code itself.

## Oracle

Condition: **the sensitive page's response lacks an effective frame restriction.** Start the
target's real application on `127.0.0.1` with an ephemeral port and request the page with the
standard-library client. No browser is needed.

- `target_reached`: the real route returned a response (any status).
- `oracle_valid`: the check reads the real response headers for the sensitive route.
- `vulnerability_observed`: the response for the sensitive page has neither
  `X-Frame-Options` (`DENY`/`SAMEORIGIN`) nor a CSP `frame-ancestors` directive restricting
  framing.
- `positive_control`: the same header check fires on a header set the probe builds with the
  frame headers removed.
- `negative_control`: the check stays silent on a header set containing
  `X-Frame-Options: DENY`, and on a route of the target that already sets it, if one exists.

## Language notes

- **Python**: Django middleware list in `settings.py`, `@xframe_options_exempt`, Flask
  `after_request` hooks, `http.server` handlers that never call `send_header`.
- **JavaScript**: `helmet()` or `helmet.frameguard`, Express apps without it, Next.js
  `headers()` configuration.
- **Java**: Spring Security `headers().frameOptions().disable()`, servlet filters.
- **Perl**: `Plack::Middleware::XFrameOptions`, Mojolicious `after_dispatch` hooks.

## Pitfalls

- A header added by a production proxy outside the repository cannot be observed; say so.
- `ALLOW-FROM` is obsolete and ignored by current browsers; treat it as absent.
- A missing header on an API that returns JSON is not clickjacking.

## Verdict guidance

Impact is modest: the attacker needs a victim to click inside a hostile page, and only
single-click actions are at risk. Keep the summary proportionate.

- `potentially_exploitable`: a page with a one-click authenticated action was served without
  frame protection; name the action.
- `likely_not_exploitable`: the cited header or middleware is present on the route, or the
  page carries no action worth framing.
- `inconclusive`: protection may be added outside the repository; name the layer.
