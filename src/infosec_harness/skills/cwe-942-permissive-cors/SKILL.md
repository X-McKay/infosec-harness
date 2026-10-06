---
name: cwe-942-permissive-cors
description: Recognize permissive cross-origin policies and missing origin checks, and define a loopback
  oracle with an untrusted Origin header. Use this when the finding is CWE-942, CWE-346 or CWE-1385.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-942: Permissive cross-domain policy (CORS)

## Use this skill when

- The finding is classified CWE-942, CWE-346 (origin validation error) or CWE-1385
  (missing WebSocket origin check), or names CORS, cross-origin or origin validation.
- Code sets `Access-Control-Allow-Origin` from the request's `Origin`, uses a wildcard with
  credentials, matches origins by substring/regex, or accepts WebSocket upgrades from any origin.

## Do not use this skill when

- The response carries no credentials and no private data (a public, unauthenticated API with
  `*` is intended).
- The issue is framing rather than reading responses — use `cwe-1021-clickjacking`.

## When another skill also applies

- `cwe-16-security-misconfiguration` routes here; **this skill wins** for any cross-origin
  setting.
- `cwe-200-information-exposure` describes what the response leaks; **this skill wins** when
  the leak to another site happens only because of the cross-origin policy.

## Procedure

**Sink.** The response header writer for `Access-Control-Allow-Origin` and
`Access-Control-Allow-Credentials`, or the WebSocket upgrade handler.

**Guard.** An exact-match allow-list of origins; `Vary: Origin` with a fixed list; a WebSocket
handshake that compares `Origin` against the allow-list before upgrading.

**Neutralized when.** An origin not on the list receives no `Access-Control-Allow-Origin`
naming it, or credentials are never allowed together with a reflected or `*` origin. Suffix
checks such as `endswith("example.com")` are not neutralizing: `evil-example.com` passes.

**Source.** The `Origin` request header, which any web page the victim visits can choose.

## Oracle

Condition: **a request with an untrusted Origin receives headers that let that origin read
the response with the victim's credentials.** Start the target's real server or handler on
`127.0.0.1` with an ephemeral port. Send requests with the standard-library client:

- `target_reached`: the real handler answered the request carrying
  `Origin: http://untrusted.invalid` (any status).
- `vulnerability_observed`: the response has `Access-Control-Allow-Origin` equal to the
  untrusted origin (or `null` when `Origin: null` is sent) together with
  `Access-Control-Allow-Credentials: true`. A WebSocket handshake answered with `101` for the
  untrusted origin also fires.
- `positive_control`: the check fires on a header set the probe builds with the reflected
  origin and credentials true.
- `negative_control`: a request with an allow-listed origin (or with no `Origin`) shows the
  expected header for that origin and the check stays silent for the untrusted one.

Use `.invalid` names only; no browser and no outside host is needed. Test a near-miss origin
(`http://allowed.example.invalid.untrusted.invalid`) when the guard is a substring match.

## Language notes

- **Python**: hand-written `send_header("Access-Control-Allow-Origin", self.headers["Origin"])`,
  `flask_cors.CORS(app, supports_credentials=True)` with default origins, Django
  `CORS_ALLOW_ALL_ORIGINS` with `CORS_ALLOW_CREDENTIALS`.
- **JavaScript**: `res.setHeader('Access-Control-Allow-Origin', req.headers.origin)`,
  `cors({ origin: true, credentials: true })`, `ws` servers without `verifyClient`.
- **Java**: Spring `@CrossOrigin(origins="*", allowCredentials="true")`,
  `allowedOriginPatterns("*")`, servlet filters echoing `Origin`.
- **Perl**: Plack middleware or Mojolicious hooks that copy `$req->header('Origin')`.

## Pitfalls

- `*` with credentials is refused by browsers; reflection plus credentials is the real hazard.
- Without credentials, reflection matters only if the response is private by other means
  (network position, IP allow-list); say which.
- Preflight (`OPTIONS`) and the actual request may be handled by different code; test both
  when the finding names one.

## Verdict guidance

- `potentially_exploitable`: the untrusted origin was reflected with credentials on a route
  that returns caller-specific data.
- `likely_not_exploitable`: the cited allow-list refused the untrusted and near-miss origins,
  with both controls passing.
- `inconclusive`: credentials or private data depend on deployment you cannot observe.
