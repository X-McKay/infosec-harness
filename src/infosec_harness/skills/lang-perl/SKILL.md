---
name: lang-perl
description: 'Conventions for reading Perl repositories: layout, dependencies, and Test::More tests.
  Use this when the repository is primarily Perl.'
metadata:
  owner: appsec
  version: 1.1.0
---

# Perl repositories

## Use this skill when

- The repository's primary language is Perl.
- You need to locate its modules, dependencies, or tests.

## Do not use this skill when

- The repository is primarily another language.
- You are planning the build itself — use `environment`.

## Procedure

- **Manifests:** `cpanfile`, `Makefile.PL`, `Build.PL`, `META.json`/`META.yml`.
- **Layout:** modules under `lib/` as `Foo/Bar.pm` (package `Foo::Bar`); scripts in `bin/`/`script/`.
- **Entry points:** CGI/PSGI handlers (Plack, Dancer, Mojolicious, Catalyst actions), CLI scripts.
- **Tests:** `t/*.t` run by `prove`, typically using `Test::More`.
- **Sinks to note:** backticks / `system` / `open "... |"`, `DBI` `do`/`prepare` with
  interpolation, `eval` of a string, `open` with untrusted paths, template `Text::...` with raw
  output.

## Completion criteria

- You can name the dependency declaration, the module layout, and the test directory.

