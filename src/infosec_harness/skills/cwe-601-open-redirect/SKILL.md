---
name: cwe-601-open-redirect
description: Untrusted input choosing a redirect destination. Use this when the finding is CWE-601 or open redirect.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-601: Open redirect

## Use this skill when

- The finding is classified CWE-601, or names open redirect or URL redirection to untrusted site.
- An untrusted value becomes the target of a redirect (`Location` header, `res.redirect(value)`,
  a meta-refresh or JavaScript `location` set from input).

## Do not use this skill when

- The hazard is CR/LF injected into the header rather than the destination — use
  `cwe-113-http-response-splitting`.
- The value is fetched server-side rather than sent to the browser — use `cwe-918-ssrf`.

## When another skill also applies

- `cwe-113-http-response-splitting` shares the `Location` sink. **That skill wins** when the value
  injects CR/LF to add headers; this skill wins when a syntactically valid URL simply sends the
  user off-site.
- `cwe-918-ssrf` also concerns an attacker-chosen URL. **That skill wins** when the *server* makes
  the request; this skill owns a redirect the *browser* follows.

## Procedure

**Sink.** Setting a redirect destination from untrusted input: `Location: <value>`,
`res.redirect(value)`, `HttpServletResponse.sendRedirect(value)`, `return redirect(value)`.

**Guard.** An allowlist of permitted hosts/paths, forcing the redirect to a relative path (rejecting
`//`, `http:`, `https:`, backslashes and other absolute forms), or mapping a key to a fixed URL.

**Neutralized when.** The destination is constrained to the application's own origin — a relative
path with no scheme and no `//` prefix, or an allowlisted host — so the caller cannot name an
external origin.

## Oracle

Condition: **the redirect destination resolved to an attacker-chosen external origin rather than
staying on the application's own site.** Call the real redirect-building function and inspect the
destination string it produced. Use a payload naming a foreign origin, such as
`https://evil.<nonce>.example/` and also protocol-relative `//evil.<nonce>.example/`. Map the
result onto `HARNESS_PROBE` (see `probe`):

- `target_reached`: the real function ran with the external payload and produced or rejected a
  destination.
- `oracle_valid`: the destination is judged by its parsed authority, not by substring.
- `vulnerability_observed`: the destination the target emits has the foreign host/origin (its
  authority is `evil.<nonce>.example`), rather than being forced relative or rejected.
- `positive_control`: a trivial `Location: <payload>` built directly shows the foreign authority,
  proving the check parses authority correctly.
- `negative_control`: a benign relative value (`/account`) through the target produces a
  same-origin destination and the check stays silent.

Use URL parsing (authority comparison), not substring matching, so `https://good.example.evil.com`
and `/\evil.com` are judged by their real host. No browser or network is needed.

## Language notes

- **Python:** Flask `redirect(value)`, bare `Location` headers in `http.server`; `urlparse` the
  result and compare `netloc`. `url_for` with a relative path is the safe form.
- **JavaScript:** Express `res.redirect(value)`; validate with `new URL(value, base)` and compare
  `origin`. A leading `//` is protocol-relative and off-origin.
- **Java:** `response.sendRedirect(value)`; `UriComponentsBuilder` with host validation is the guard.
- **Perl:** CGI `print redirect($url)` / Mojolicious `$c->redirect_to($url)`; parse with `URI` and
  check the host.

## Pitfalls

- Substring allowlists (`contains("good.com")`) are bypassable (`good.com.evil.com`,
  `evil.com/good.com`); judge by parsed authority.
- Protocol-relative `//host` and backslash variants `/\host` or `\/\/host` are off-origin on many
  parsers; include them in the payload set.
- An open redirect is often lower severity than injection; keep the finding's stated severity and
  scope, and note it is a redirect, not code execution.

## Verdict guidance

- `potentially_exploitable`: the destination can carry an attacker-chosen external authority with
  no allowlist or relative-only guard, and the probe observed a foreign origin in the output.
- `likely_not_exploitable`: cite the allowlist or relative-only enforcement line, with a complete
  probe showing the external payload forced same-origin or rejected.
- `inconclusive`: the redirect builder could not be exercised, or the host-parsing behaviour was unobserved.
