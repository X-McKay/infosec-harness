---
name: cwe-470-unsafe-reflection
description: Recognize class, module or function names chosen by untrusted input and define a probe-
  owned marker oracle. Use this when the finding is CWE-470 or input drives dynamic dispatch.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-470: Unsafe reflection

## Use this skill when

- The finding is classified CWE-470, or names unsafe reflection or externally controlled
  class/method selection.
- An untrusted string selects what runs: `Class.forName(name)`, `getattr(module, name)()`,
  `importlib.import_module(name)`, `obj[name]()`, `require(name)`, Perl `$class->new` or
  `&{"$name"}` with a caller-chosen name.

## Do not use this skill when

- The value is evaluated as source text (`eval`, `exec`, `Function`) — use
  `cwe-94-code-injection`.
- The value reaches a deserializer that instantiates named types — use
  `cwe-502-deserialization`.

## When another skill also applies

- `cwe-94-code-injection` also fires on dynamic dispatch built from strings. **That skill
  wins** whenever the value is parsed as code; this skill covers lookup by name with no
  parsing.
- `cwe-502-deserialization` **wins** when the class name arrives inside serialized data and
  the reader constructs it.

## Procedure

**Sink.** The lookup and invocation by name: `getattr(obj, name)(*args)`,
`globals()[name]`, `Class.forName(n).getDeclaredConstructor().newInstance()`,
`Method.invoke`, `handlers[req.query.action]()`, `require(userPath)`.

**Guard.** A fixed mapping from accepted names to callables; an allow-list checked before
lookup; a required prefix that also excludes dunder and inherited names; `Object.hasOwn` on a
null-prototype map.

**Neutralized when.** The set of callables reachable from any input is exactly the intended
set. A `startswith("handle_")` prefix or a dictionary lookup on an ordinary object can still
expose inherited members (`__class__`, `constructor`, `toString`).

**Source.** Request parameters, route segments, message types, configuration from users.

## Oracle

Condition: **an input chose a callable outside the intended set and the target invoked it.**
Prefer a callable that already exists in the reachable namespace and only returns or records
something observable, such as a non-handler helper in the same module, or an inherited member
(`__class__`, `constructor`) whose result is distinguishable. When the lookup scope is a
module path or class path, place a probe-owned module under `/workspace/repo` (never inside
the original source tree's files) whose only effect is creating `/tmp/harness_canary_<nonce>`.

- `target_reached`: the real dispatcher ran with the out-of-set name, including when it
  rejected it.
- `vulnerability_observed`: the out-of-set callable's distinguishing result was returned, or
  the canary exists after the target call and did not before.
- `positive_control`: invoking the same callable directly in the probe yields the result or
  canary, proving it is observable.
- `negative_control`: an intended name dispatches normally and nothing out-of-set is observed.

## Language notes

- **Python**: `getattr`, `globals()`, `importlib.import_module`, `__import__`, `pydoc.locate`.
- **JavaScript**: `obj[name]()` on objects with prototypes (`constructor`, `__proto__`),
  `require(name)`, `import(name)`, `global[name]`.
- **Java**: `Class.forName`, `ClassLoader.loadClass`, `Method.invoke`, Spring bean names from
  input, `ScriptEngineManager` (route that to `cwe-94-code-injection`).
- **Perl**: `$class->new` where `$class` is input, `can($name)->()`, symbolic references
  `&{"main::$name"}` (check for `use strict 'refs'`), `require $module`.

## Pitfalls

- A dispatch table keyed by name is usually safe in Python dictionaries but not in plain
  JavaScript objects; test an inherited key.
- Do not plant a module inside the original source files; add new files only, as `probe`
  requires.
- Reaching a harmless built-in proves the selection; state that impact depends on which
  callables are reachable with which arguments.

## Verdict guidance

- `potentially_exploitable`: an out-of-set callable ran through the real dispatcher; name
  which callables an attacker can reach and with what arguments.
- `likely_not_exploitable`: the cited allow-list or fixed mapping refused the out-of-set and
  inherited names, with both controls passing.
- `inconclusive`: the lookup scope depends on runtime plugins you could not load.
