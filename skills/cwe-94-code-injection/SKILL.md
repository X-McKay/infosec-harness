---
name: cwe-94-code-injection
description: "Recognize code-injection sources and sinks (eval/dynamic exec) and define a canary oracle."
---

# CWE-94: Code injection

**Sink.** Evaluating untrusted input as program code or templates: `eval`, `exec`,
`Function(...)`, dynamic template engines with an untrusted template, expression-language
evaluators.

**Source.** Untrusted values reaching the evaluator.

**Neutralized when.** No dynamic evaluation of untrusted input occurs — a data parser
(`json.loads`, `ast.literal_eval`) or a fixed template with data-only variables is used.

## Oracle

Use a marker or canary oracle. Craft the input so that, *if* it is evaluated as code, a benign
expression runs whose only effect is to make the observable signal — e.g. it evaluates to a
value containing `HARNESS_ORACLE::<nonce>` that the test then prints, or it creates
`/tmp/harness_canary_<nonce>`.

- Print the precondition marker before invoking the sink.
- Fire the oracle only from that injected evaluation actually running. If the code treated the
  input as inert data, the expression never runs — a valid negative.

The injected expression must be inert (produce the marker only); never perform any other
action.
