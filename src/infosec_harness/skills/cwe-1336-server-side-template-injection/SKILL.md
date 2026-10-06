---
name: cwe-1336-server-side-template-injection
description: 'Server-side template injection: untrusted input becomes the template itself. Use this when the finding is CWE-1336.'
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-1336: Server-side template injection (SSTI)

## Use this skill when

- The finding is classified CWE-1336, or names SSTI or template injection.
- An untrusted value becomes part of the template *source* a server-side engine compiles and
  renders: Jinja2, Mako, Twig-style, Freemarker, Velocity, EJS/Pug/Handlebars, Perl Template Toolkit.

## Do not use this skill when

- The value is only a *variable* passed to a fixed template (`render(tpl, name=value)`) — that is
  ordinary data binding; check for `cwe-79-xss` on the rendered output instead.
- The value reaches an embedded expression language on its own — use
  `cwe-917-expression-language-injection`.

## When another skill also applies

- `cwe-917-expression-language-injection` and `cwe-94-code-injection` also evaluate attacker text.
  **This skill wins** when the untrusted value is the *template string itself* (concatenated into
  the template or passed where a template is expected). CWE-917 wins for a bare expression-language
  evaluator; CWE-94 wins for a general-language `eval`/`exec`.
- `cwe-79-xss` owns unsafe *output* of data through a template. **That skill wins** when the value
  is template data rendered into HTML; this skill owns the value being template *code*.

## Procedure

**Sink.** Compiling/rendering a template whose source includes untrusted input:
`Template("Hello " + name).render()`, `env.from_string(user)`, `render_template_string(user)`,
Freemarker `new Template(name, new StringReader(user), cfg)`, EJS `ejs.render(user)`,
Template Toolkit `$tt->process(\$user)`.

**Guard.** The untrusted value is passed as *data* to a fixed template, a sandboxed/restricted
template environment (Jinja2 `SandboxedEnvironment`, a logic-less engine like Mustache), or a
strict allowlist of templates chosen by key rather than supplied by the caller.

**Neutralized when.** The caller can choose only template *data*, never template *source*; or the
engine is logic-less / sandboxed so expressions cannot evaluate; or template selection is by a
fixed key map.

## Oracle

Condition: **the engine evaluated attacker text as template code.** Inject an inert arithmetic
expression in the engine's own delimiters whose result is absent from the input, such as
`{{7*191}}` → `1337` (Jinja2/Twig), `${7*191}` (Freemarker/Mako-style `${}`), `<%= 7*191 %>` (EJS),
`[% 7*191 %]` (Template Toolkit). The expression only computes a number; never call a filter or
method that runs a command, reads a file or opens a socket. Map the result onto `HARNESS_PROBE`
(see `probe`):

- `target_reached`: the real render entry point received the payload as template source, including
  when a sandbox or data-only path refuses to evaluate it.
- `oracle_valid`: the payload uses the engine's own delimiters and its computed result is
  absent from the input.
- `vulnerability_observed`: the computed result (`1337`) appears in the rendered output.
- `positive_control`: the same engine rendering that payload directly yields the result, proving
  the engine and delimiters are right.
- `negative_control`: the payload passed as template *data* to a fixed template, or a benign
  value, renders without computing (the literal `{{7*191}}` or escaped text appears).

## Language notes

- **Python:** Jinja2 `env.from_string` / `render_template_string` evaluate `{{ }}`; Mako `Template(text)`
  evaluates `${ }` and `<% %>`. `SandboxedEnvironment` blocks attribute access, not arithmetic.
- **JavaScript:** EJS `<%= %>`, Pug/Handlebars compile user templates; Handlebars is logic-less so
  arithmetic may not evaluate — pick a helper-free observable or treat absence as a negative.
- **Java:** Freemarker `${ }` / `<#...>`, Velocity `#set` / `$`. Freemarker evaluates arithmetic in `${}`.
- **Perl:** Template Toolkit `[% %]`; `$tt->process(\$user_string)` compiles the user string as a template.

## Pitfalls

- Rendering the literal `{{7*191}}` unchanged means data binding, not SSTI — a clean negative.
- Logic-less engines (Mustache, strict Handlebars) may echo expressions without evaluating; do not
  read that as a block if the engine simply has no arithmetic — scope the conclusion to the engine.
- Keep payloads to arithmetic/string math; template RCE gadgets exceed a diagnosis and may escape
  the intended observation.

## Verdict guidance

- `potentially_exploitable`: untrusted input forms template source in a non-sandboxed engine and
  the probe observed the computed result in the output.
- `likely_not_exploitable`: cite the data-only binding, the sandboxed environment, or the fixed
  template map, with a complete probe showing the payload rendered as literal text.
- `inconclusive`: the engine could not be rendered, or whether the value was source or data stayed unresolved.
