---
name: cwe-862-missing-authorization
description: Recognize missing or incorrect authorization and insecure direct object references, and define a two-principal oracle.
  Use this when the finding is CWE-862, CWE-863 or CWE-639, or an authenticated caller can reach another principal's object.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-862: Missing authorization (also CWE-863, CWE-639 IDOR)

## Use this skill when

- The finding is classified CWE-862, CWE-863 (incorrect authorization) or CWE-639
  (authorization bypass through a user-controlled key, IDOR).
- A handler looks an object up by a caller-supplied id, path segment or field and returns or
  changes it without comparing its owner, tenant or role with the authenticated principal.
- A role or permission check exists but tests the wrong attribute, the wrong object, or a
  value the caller supplies (a `role` field in the request body).

## Do not use this skill when

- The caller is not authenticated at all, or authentication itself can be bypassed — use
  `cwe-287-improper-authentication`.
- The cross-principal effect comes from a forged request riding the victim's session — use
  `cwe-352-csrf`.
- The caller-supplied key is a file path — use `cwe-22-path-traversal`.

## When another skill also applies

- `cwe-287-improper-authentication` also fires when a route has neither authentication nor
  authorization. **That skill wins** if no identity is established anywhere on the path; this
  skill wins once a principal exists and the question is what it may touch.
- `cwe-89-sql-injection` wins when the id widens the query structurally; this skill covers a
  well-formed id that simply belongs to someone else.

## Procedure

**Sink.** Returning, updating or deleting an object selected by a caller-controlled key:
`get(id)`, `UPDATE ... WHERE id = ?` with no owner predicate, `find_by_id`, file or record
handlers keyed by name.

**Guard.** The ownership, tenant or role comparison between the authenticated principal and
the object: an owner predicate in the query, a policy call, a decorator checking a role.
Note where the principal comes from: the session (trusted) or the request (untrusted).

**Source.** Ids in path segments, query strings, bodies and headers; role or owner fields the
caller sends.

**Neutralized when.** The object lookup is scoped to the principal from the session
(`WHERE id = ? AND owner = ?`), or a check after lookup rejects a mismatch before any data or
side effect leaves the handler, for every method (GET, PUT, DELETE) the route accepts.

## Oracle

Condition: **a second principal's object is returned or mutated by a request authenticated
as the first principal.** Seed a probe-owned store with two principals, Alice and Bob, each
owning one object holding a distinct nonce. Authenticate as Alice through the target's real
session or token mechanism, or pass Alice as the principal exactly as the real caller does.

- `target_reached`: the real handler ran for Alice with Bob's object id, including when it
  answers 403 or 404.
- `vulnerability_observed`: Bob's nonce appears in the response, or Bob's object changed in
  the store after Alice's request.
- `positive_control`: Alice requesting her own object gets her nonce, proving the oracle sees
  a successful read.
- `negative_control`: Alice requesting a nonexistent id returns no nonce and changes nothing.
  If the target denies everything, including Alice's own object, the positive control fails
  and the probe is incomplete.

## Language notes

- **Python:** `http.server` handlers parsing `self.path`, Flask `<int:id>` routes, Django
  `Model.objects.get(pk=...)` without `owner=request.user`, DRF `get_queryset` not filtered.
- **JavaScript:** Express `req.params.id` passed to `findById`; middleware that checks
  `req.user` exists but not ownership; `req.body.role` trusted.
- **Java:** Spring `@PathVariable` ids with `@PreAuthorize` missing or checking only a role;
  JPA `findById`.
- **Perl:** CGI `param('id')` into a lookup; Dancer/Mojolicious routes; `$session->{user}`
  never compared with the row's owner.

## Pitfalls

- Sequential ids make IDOR easy to exploit, but random ids do not authorize anything; treat
  id unpredictability as a limitation, not a guard.
- Check every method on the route. A guarded GET with an unguarded PUT is still vulnerable.
- Do not authenticate as Bob to fetch Bob's object; the oracle needs Alice's credentials.

## Verdict guidance

- `potentially_exploitable`: Bob's nonce or state reached Alice through the real handler.
- `likely_not_exploitable`: cite the owner predicate or check line that stopped the request,
  with the positive control passing.
- `inconclusive` when authorization is delegated to configuration or a service absent from the
  repository; name it.
