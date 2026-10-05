---
name: cwe-94-code-injection
description: Recognize code-injection sources and sinks (eval and dynamic exec) and define a canary
  oracle. Use this when the finding is CWE-94 or untrusted input is evaluated as program source.
metadata:
  owner: appsec
  version: 2.0.0
---

# CWE-94: Code injection

## Use this skill when

- The finding is classified CWE-94, or names code injection or eval injection.
- A caller-supplied value reaches `eval`, `exec`, `compile`, `Function(...)`, or a template engine that executes expressions.

## Do not use this skill when

- The value reaches a shell rather than a language evaluator — use `cwe-78-os-command-injection`.
- The value is deserialized rather than evaluated — use `cwe-502-deserialization`.

## When another skill also applies

- `cwe-78-os-command-injection` also fires when the source this evaluator runs goes on to invoke a shell, and each skill redirects to the other. **This skill wins** whenever the value is parsed as program source before anything else consumes it; it is command injection only when the value reaches a shell without being evaluated on the way.

## Procedure

**Sink.** Evaluating untrusted input as program code or templates: `eval`, `exec`,
`Function(...)`, dynamic template engines with an untrusted template, expression-language
evaluators.

**Source.** Untrusted values reaching the evaluator.

**Neutralized when.** No dynamic evaluation of untrusted input occurs — a data parser
(`json.loads`, `ast.literal_eval`) or a fixed template with data-only variables is used.

## Oracle

Condition: **the target evaluated attacker input as code.** Inject an inert expression whose
result is absent from the input text, such as `'h'+'<nonce>'` evaluating to `h<nonce>`, so an
echoed payload cannot fire the check. Match the payload to the evaluation context (close an
enclosing string literal first). The expression only produces that value; never perform any
other action. Map the result onto `HARNESS_PROBE` (see `probe`):

- `target_reached`: the real evaluator entry point received the payload, including when it
  treats it as data or rejects it.
- `vulnerability_observed`: the computed `h<nonce>` appears in the target's output or state.
- `positive_control`: the language's evaluator run directly on the same payload in the same
  context yields `h<nonce>`.
- `negative_control`: a benign literal value through the target yields no `h<nonce>`.
