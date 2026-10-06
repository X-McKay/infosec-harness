---
name: cwe-1321-prototype-pollution
description: Recognize JavaScript merge, extend and set-by-path code that lets keys reach a shared
  prototype, and define a restore-after oracle. Use this when the finding is CWE-1321.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-1321: Prototype pollution

## Use this skill when

- The finding is classified CWE-1321, or names prototype pollution.
- JavaScript code copies keys from untrusted data recursively (`merge`, `extend`,
  `defaultsDeep`, `deepAssign`) or writes along a caller-supplied path (`set(obj, path, v)`),
  without excluding `__proto__`, `constructor` and `prototype`.

## Do not use this skill when

- The language is not JavaScript or TypeScript (Python class attributes — see
  `cwe-915-mass-assignment`).
- The copy is shallow `Object.assign` from `JSON.parse` output onto a fresh object: the
  `__proto__` key becomes an own property, not the prototype. Confirm before dismissing.

## When another skill also applies

- `cwe-915-mass-assignment` also fires for request-body merges. **This skill wins** when the
  write reaches a shared prototype; that skill wins for own attributes.
- `cwe-94-code-injection` or `cwe-78-os-command-injection` **win** if a polluted property is
  later read by an evaluator or a spawn call: report the gadget there, and cite this skill for
  how the property got set.

## Procedure

**Sink.** The assignment `target[key] = value` inside a recursive copy or path walk, where
`key` comes from untrusted data and `target` can become `Object.prototype` via `__proto__`
or `constructor.prototype`.

**Guard.** Skipping `__proto__`, `constructor` and `prototype` keys; `Object.hasOwn` checks
before descending; creating targets with `Object.create(null)`; using `Map`; schema validation
that rejects unknown keys; `Object.freeze(Object.prototype)` at start-up.

**Neutralized when.** No key sequence from the input can make the write target a shared
prototype on every recursive and path-walking branch.

**Source.** Parsed JSON bodies, query strings parsed into nested objects, configuration files
from users. `JSON.parse` keeps `"__proto__"` as an ordinary key, which is what makes the
recursive copy dangerous.

## Oracle

Condition: **after the real call, a property the input named exists on `Object.prototype`.**
Use a unique property name such as `harness_<nonce>`. Wrap every check in `try`/`finally` that
deletes the property from `Object.prototype` so later checks and the runner are unaffected.

- `target_reached`: the real merge or set function ran with
  `JSON.parse('{"__proto__":{"harness_<nonce>":true}}')` (or the path form
  `"__proto__.harness_<nonce>"` / `"constructor.prototype.harness_<nonce>"`), whether it
  copied, skipped or rejected the key.
- `vulnerability_observed`: `({}).harness_<nonce> === true` after the call.
- `positive_control`: assigning `Object.prototype.harness_<nonce> = true` directly in the
  probe makes the check fire; then delete it and confirm `({}).harness_<nonce>` is undefined.
- `negative_control`: a benign nested object through the same function merges normally, and
  the check stays silent.

Try both the `__proto__` and the `constructor.prototype` forms before concluding a guard
works; many guards block only one.

## Language notes

- **JavaScript**: hand-written recursive merges, `lodash` `merge`/`set`/`defaultsDeep` in old
  versions (check the installed version, see `cwe-1104-vulnerable-third-party-component`),
  `qs` with `allowPrototypes`, `jQuery.extend(true, ...)`.
- **TypeScript**: the same at runtime; types do not prevent the key.
- **Python, Java, Perl**: no shared mutable prototype; route class-attribute writes to
  `cwe-915-mass-assignment` and reflective lookups to `cwe-470-unsafe-reflection`.

## Pitfalls

- An object literal `{__proto__: {...}}` in probe code sets the literal's prototype instead
  of creating a key; build the input with `JSON.parse`.
- Forgetting to restore `Object.prototype` contaminates the negative control.
- Pollution alone is a primitive; impact needs a later read of the property. State what reads it,
  or keep the claim to the pollution itself.

## Verdict guidance

- `potentially_exploitable`: the property reached `Object.prototype` through the real
  function with request-shaped input; name the reader if one exists.
- `likely_not_exploitable`: the cited key filter or null-prototype target blocked both forms,
  with both controls passing.
- `inconclusive`: the function is reachable only through a parser whose behaviour you could
  not run; say which.
