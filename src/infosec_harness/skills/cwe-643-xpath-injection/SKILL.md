---
name: cwe-643-xpath-injection
description: Untrusted input built into an XPath or XQuery expression. Use this when the finding is CWE-643/91.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-643 / CWE-91: XPath injection

## Use this skill when

- The finding is classified CWE-643 or CWE-91, or names XPath, XQuery or blind XPath injection.
- An untrusted value is concatenated or formatted into an XPath/XQuery expression evaluated
  against a document (`//user[name='<value>']`).

## Do not use this skill when

- The query language is SQL, LDAP or a NoSQL store — use `cwe-89-sql-injection`, `cwe-90-ldap-injection` or `cwe-943-nosql-injection`.
- The untrusted XML is parsed with entities, not queried — use `cwe-611-xxe`.

## When another skill also applies

- `cwe-90-ldap-injection` and `cwe-943-nosql-injection` share the "value changes query structure"
  shape. **This skill wins** only when the expression is XPath/XQuery evaluated against XML;
  classify by the evaluator the value reaches.
- `cwe-611-xxe` owns the parser's entity handling for the same document. **That skill wins** for
  entity/DTD expansion; this skill owns the query evaluated over the parsed tree.

## Procedure

**Sink.** An XPath/XQuery evaluation whose expression string was built from untrusted input:
`tree.findall("//user[name='" + value + "']")`, `xpath.evaluate(expr)`, `XQuery` with
interpolation.

**Guard.** Variable binding / parameterized XPath (`$name` bound through a resolver), or escaping
of quotes and metacharacters, or a strict allowlist applied before the value joins the expression.

**Neutralized when.** The value is supplied as a bound variable the evaluator treats as a single
operand, or every quote and metacharacter is escaped for its context, or the value is validated
against a strict pattern.

## Oracle

Condition: **the untrusted value changed the structure of the XPath expression rather than being
treated as a single string operand.** Build a small in-memory XML document the probe owns, with
one node the intended predicate should return and one marked secret it must not. Drive the real
evaluator (not a stub). Use a widening payload matched to the quoting context, such as
`' or '1'='1` for `name='<value>'`. Map the result onto `HARNESS_PROBE` (see `probe`):

- `target_reached`: the real query function ran with the payload and built or rejected the
  expression, including when escaping makes it match nothing.
- `oracle_valid`: the document holds one intended and one secret node, and the payload matches
  the quoting context.
- `vulnerability_observed`: the node the intended predicate excludes (the secret node) is
  returned, or the compiled expression shows the operator the value introduced.
- `positive_control`: the equivalent concatenated expression, evaluated directly with the
  payload against the same document, returns the excluded node.
- `negative_control`: a benign value through the target returns only the intended node.

## Language notes

- **Python:** `xml.etree.ElementTree` `findall` supports a limited predicate subset; `lxml`
  `xpath()` is full XPath 1.0 and takes `xpath(expr, name=value)` variables as the safe form.
- **JavaScript:** `xpath` npm package `select(expr, doc)`; parameterization is not built in, so
  concatenated expressions are the sink.
- **Java:** `XPath.compile(expr)`; the safe form binds a `XPathVariableResolver` and uses `$name`.
- **Perl:** `XML::LibXML` `findnodes($expr)`; `$xpc->findnodes` with values interpolated into the
  string is the sink.

## Pitfalls

- ElementTree's predicate language is narrow; a payload valid in full XPath may be a parse error
  there. Match the payload to the evaluator actually used.
- A quote-balanced payload (`' or '1'='1`) avoids the syntax errors an unbalanced one causes;
  confirm the positive control fires before trusting an empty result.
- Returning *all* nodes and returning the *secret* node are different; seed a node the intended
  predicate genuinely excludes so the widening is observable.

## Verdict guidance

- `potentially_exploitable`: the value reaches an unescaped, unbound position in the expression
  and the probe observed the excluded node returned or the structure changed.
- `likely_not_exploitable`: cite the variable binding or escape line, with a complete probe
  showing the payload treated as a literal operand.
- `inconclusive`: no document/evaluator could be exercised, or the escaping behaviour was unobserved.
