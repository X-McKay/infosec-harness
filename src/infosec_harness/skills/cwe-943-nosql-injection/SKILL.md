---
name: cwe-943-nosql-injection
description: Recognize NoSQL query and operator injection (MongoDB-style, JSON query objects) and
  define a deterministic result oracle. Use this when the finding is CWE-943 or untrusted input shapes a NoSQL query.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-943: NoSQL injection

## Use this skill when

- The finding is classified CWE-943, or names NoSQL, MongoDB or query-operator injection.
- An untrusted value becomes part of a query object or query string for a document/key-value store
  (`{username: req.body.username}` where the value may be an object), or a `$where` / JavaScript
  query clause.

## Do not use this skill when

- The store is a relational database queried with SQL — use `cwe-89-sql-injection`.
- The value reaches a `$where` evaluated as JavaScript and the finding is about that code
  evaluation specifically — consider `cwe-94-code-injection` for the evaluator; this skill owns the
  operator/structure injection.

## When another skill also applies

- `cwe-89-sql-injection`, `cwe-90-ldap-injection` and `cwe-643-xpath-injection` share the
  "value changes query structure" shape. **This skill wins** only when the store is a NoSQL
  document/key-value engine; classify by the datastore the query reaches.
- Use `probe` for source integrity, controls and evidence rules.

## Procedure

**Sink.** Building a query where an untrusted value can become an operator or sub-document rather
than a scalar: `collection.find({user: input})` when `input` is a parsed JSON object, string
concatenation into a query, or a `$where` / `mapReduce` clause carrying input.

**Guard.** Coercing the value to a scalar (`str(input)`), a schema/type check that rejects
objects, an allowlist of permitted operators, or a parameterized/typed query API.

**Neutralized when.** The value is forced to a scalar before it reaches the query, or a schema
rejects non-scalar input, or operators are allowlisted, so `{"$ne": null}`-style payloads cannot
enter the query tree.

## Oracle

Condition: **the untrusted value introduced a query operator or clause instead of matching as a
scalar.** Use an in-memory document store the probe owns — a small list filtered by the same query
semantics, an embedded Mongo-compatible fake that honours operators (`mongomock`), or a hand-written
matcher that implements `$ne`/`$gt` — never a stub that ignores the query. Seed one document the
intended scalar query returns and one it must not. Use an operator payload such as
`{"$ne": "no-match"}` or `{"$gt": ""}`. Map the result onto `HARNESS_PROBE` (see `probe`):

- `target_reached`: the real query function ran with the payload and built or rejected the query,
  including when a scalar coercion flattens it to a literal.
- `vulnerability_observed`: the document the intended scalar query excludes is returned, or the
  built query object shows the attacker's operator key.
- `positive_control`: the equivalent query built directly with the operator payload returns the
  excluded document, proving the store honours operators.
- `negative_control`: a benign scalar value through the target returns only the intended document.

## Language notes

- **JavaScript:** Express + MongoDB `collection.find({user: req.body.user})`; a JSON body makes
  `req.body.user` an object, so `{"$ne": null}` injects. `mongo-sanitize` or forcing `String(x)` is the guard.
- **Python:** PyMongo `collection.find({"user": value})`; a value parsed from JSON can be a dict.
  Coercing with `str(value)` or a schema (pydantic) is the guard. `mongomock` gives an offline store.
- **Java:** MongoDB driver `Filters.eq("user", value)` with a typed scalar is safe; building a
  `Document` from untrusted parsed JSON is the sink.
- **Perl:** `MongoDB::Collection` `find({ user => $value })`; a `$value` that is a hashref injects operators.

## Pitfalls

- The injection depends on the value arriving as a *structured* object — confirm the real parsing
  path yields a dict/hashref, not a string, before concluding.
- A store that silently ignores unknown operators produces a false negative; use a matcher that
  genuinely implements the operator and confirm the positive control.
- `$where` with JavaScript is a second, distinct hazard (code evaluation); scope the oracle to the
  mechanism the finding names.

## Verdict guidance

- `potentially_exploitable`: an untrusted structured value reaches the query with no scalar
  coercion or operator allowlist, and the probe observed an excluded document returned.
- `likely_not_exploitable`: cite the scalar coercion, schema rejection or operator allowlist, with
  a complete probe showing the payload matched as a literal or rejected.
- `inconclusive`: no store could be exercised, or whether the value arrives structured was unresolved.
