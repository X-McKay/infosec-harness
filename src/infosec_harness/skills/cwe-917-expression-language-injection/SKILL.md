---
name: cwe-917-expression-language-injection
description: Expression-language injection (EL, OGNL, SpEL, MVEL). Use this when the finding is CWE-917.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-917: Expression-language injection

## Use this skill when

- The finding is classified CWE-917, or names EL, OGNL, SpEL, MVEL or expression-language injection.
- An untrusted value reaches an expression evaluator: JSP/JSF EL, Struts/OGNL, Spring
  `SpelExpressionParser`, MVEL, or a framework that evaluates `${...}` / `#{...}` on user input.

## Do not use this skill when

- The value is evaluated as full program source by a language interpreter — use
  `cwe-94-code-injection`.
- The value is rendered through a template engine's syntax — use
  `cwe-1336-server-side-template-injection`.

## When another skill also applies

- `cwe-94-code-injection` and `cwe-1336-server-side-template-injection` overlap because all three
  evaluate attacker text. **This skill wins** when the evaluated grammar is an embedded expression
  language (EL/OGNL/SpEL/MVEL) invoked on a value, not a whole template document and not a general
  interpreter's `eval`. SSTI wins when the value is the *template*; CWE-94 wins when it is program source.
- Use `probe` for source integrity, controls and evidence rules.

## Procedure

**Sink.** An expression evaluator fed untrusted input: `ExpressionParser.parseExpression(x)
.getValue()`, OGNL `Ognl.getValue(x, root)`, `MVEL.eval(x)`, a JSP/JSF page that evaluates EL in a
user-controlled attribute.

**Guard.** No evaluation of untrusted input (the value is a *data* parameter the expression reads,
not the expression text), a restricted/sandboxed evaluation context, or a strict allowlist of
permitted expressions.

**Neutralized when.** The untrusted value is bound as a variable the fixed expression reads
(`#value` resolved from a data map) rather than being parsed as expression text, or evaluation is
removed entirely.

## Oracle

Condition: **the target evaluated attacker text as an expression.** Inject an inert arithmetic or
string expression whose result is absent from the input text, such as `${7*191}` → `1337` or
`'h'+'<nonce>'`, so an echoed payload cannot fire the check. Match the delimiters to the engine
(`${...}`, `#{...}`, bare OGNL). The expression only computes a value; never call a method that
runs a command, reads a file or touches the network. Map the result onto `HARNESS_PROBE` (see
`probe`):

- `target_reached`: the real evaluator entry point received the payload, including when it treats
  it as data or rejects it.
- `oracle_valid`: the expression uses the engine's delimiters and its result is absent from the
  input text.
- `vulnerability_observed`: the computed result (`1337`, `h<nonce>`) appears in the target's
  output or state.
- `positive_control`: the same engine run directly by the probe on the payload yields the result,
  proving the engine and check work.
- `negative_control`: a benign literal value through the target yields no computed result.

## Language notes

- **Java:** SpEL `SpelExpressionParser().parseExpression(x).getValue()`; OGNL `Ognl.getValue`;
  MVEL `MVEL.eval`. JSP/JSF EL evaluates `${}`/`#{}` in page attributes. A `SimpleEvaluationContext`
  (SpEL) or sandboxed OGNL `MemberAccess` is the restricted-context guard.
- **Python:** no native EL, but `simpleeval`, `asteval` or a `${}` resolver that calls `eval` is
  equivalent; prefer `cwe-94-code-injection` when it is plain `eval`/`exec`.
- **JavaScript:** libraries like `angular-expressions` or `jsonpath` evaluators; `new Function` is
  CWE-94, not this skill.
- **Perl:** no mainstream EL; a module that evaluates `${...}` via string `eval` is CWE-94.

## Pitfalls

- `${7*191}` returning the literal string `${7*191}` means the value was *not* evaluated — a clean
  negative, not a near miss.
- Some engines evaluate only in specific contexts (a JSF attribute, not a body); reach the real
  context, not a convenient helper.
- Keep the payload to arithmetic or string building; a property-navigation payload can reach a
  method call, which exceeds a diagnosis.

## Verdict guidance

- `potentially_exploitable`: the value is parsed as expression text in an unrestricted context and
  the probe observed the computed result.
- `likely_not_exploitable`: cite the variable binding, the restricted context, or the removal of
  evaluation, with a complete probe showing the payload unevaluated.
- `inconclusive`: the engine could not be exercised, or the evaluation context was not reached.
