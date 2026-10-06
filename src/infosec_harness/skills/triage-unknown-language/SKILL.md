---
name: triage-unknown-language
description: 'Procedure for a repository in a language or toolchain with no lang-* skill: identify the
  runtime, read to the sink, decide what can execute, define an oracle, fall back honestly. Use this when no lang-* skill matches.'
metadata:
  owner: appsec
  version: 1.0.0
---

# Triage in an unfamiliar language

## Use this skill when

- No `lang-*` skill matches the code holding the finding's sink (for example Elixir, Erlang,
  Haskell, OCaml, Swift, Objective-C, Lua, Dart, Zig, Nim, R, Julia, Clojure, Solidity, COBOL).
- The sink sits in a template, query, configuration or DSL file executed by another program.

## Do not use this skill when

- A `lang-*` skill matches: load it instead, even if its toolchain turns out to be absent.

## Ground rules

Skills carry expertise and grant no permissions. A configured name is not execution evidence:
a Dockerfile `FROM`, a `.tool-versions` entry or a CI job naming a runtime does not show that
runtime exists here or that anything ran. Only a `run_probe` receipt shows execution.

## Procedure

1. **Identify the runtime and build system.** Count file extensions
   (`find . -type f -not -path './.git/*' -name '*.*' | sed 's/.*\.//' | sort | uniq -c | sort -rn | head`;
   `git` may not be installed), read the
   manifests and shebangs. Typical markers: `mix.exs` (Elixir), `rebar.config` (Erlang),
   `*.cabal`/`stack.yaml` (Haskell), `dune-project` (OCaml), `Package.swift` (Swift),
   `*.rockspec` (Lua), `pubspec.yaml` (Dart), `build.zig` (Zig), `DESCRIPTION` (R),
   `Project.toml` (Julia), `deps.edn`/`project.clj` (Clojure, a JVM language),
   `foundry.toml`/`hardhat.config.*` (Solidity). `CMakeLists.txt` or `meson.build` usually
   means C or C++: use `lang-c-cpp`.
2. **Locate the sink by reading.** Open the finding's file and line, then `search` for callers
   up to an entry point. Most sinks have a familiar shape whatever the language: a process
   spawn, a query string, a file path, an evaluator, a deserializer, an HTTP client, a template
   render, a raw memory operation. Name the source, the guard and the neutralizing condition,
   and load the matching `cwe-*` skill (or `triage-unknown-cwe`).
3. **Decide whether anything here can execute the real code.** The image provides Python 3.12,
   Java 17 with Maven, Node.js with npm, Perl, `gcc`, `make` and bash. Check the language's
   own runtime with `command -v`. In order of preference:
   - The language's runtime is present: write the probe in that language, borrowing the
     closest skill's conventions (a scripting language like `lang-python`, a compiled one
     like `lang-c-cpp` or `lang-go`, a JVM language like `lang-jvm-other`).
   - The code compiles to something an available runtime loads, built here from this
     snapshot (JVM bytecode via Maven; a C ABI library loaded with Python `ctypes`).
   - The target is a program you can build and drive from outside with argv, stdin, files or a
     loopback socket, from a Python or shell probe that prints the line.
   - Otherwise nothing here reaches the target. Testing the payload against the sink's
     interpreter alone (the SQL in SQLite, the command in `sh`) is a positive control at most,
     never `target_reached`.
4. **Define the oracle anyway.** Write down the finding-shaped input, the observable condition,
   and the positive and negative controls, mapped to the five `HARNESS_PROBE` fields as `probe`
   defines them. If you can run it, run it; if you cannot, the summary still states it so the
   gap is precise and reproducible by someone with the toolchain.
5. **Fall back honestly.** Without a complete probe the verdict is `inconclusive`. Name the
   exact capability gap in the summary (`command -v mix` printed nothing; the image has no
   Erlang/OTP), list what reading established with cited lines, and say which probe would
   decide the finding.

## Never

- Rewrite or transliterate the target into Python or another available language: a
  reimplementation is a stand-in, reports what you wrote rather than what the code does, and
  makes `target_reached` false.
- Download a runtime, compiler, package manager or prebuilt binary, or run a committed binary
  of unknown provenance as if it were built from this source.
- Treat an unrunnable target as safe: an unexecuted path is not a blocking condition.

## Completion criteria

- You can name the language, runtime and build system, the sink line and its entry point,
  which execution route you used or why none exists, and the oracle you ran or would run.
