---
name: lang-perl
description: "Conventions for reading Perl repos: layout, dependencies, and Test::More tests."
---

# Perl repositories

- **Manifests:** `cpanfile`, `Makefile.PL`, `Build.PL`, `META.json`/`META.yml`.
- **Layout:** modules under `lib/` as `Foo/Bar.pm` (package `Foo::Bar`); scripts in `bin/`/`script/`.
- **Entry points:** CGI/PSGI handlers (Plack, Dancer, Mojolicious, Catalyst actions), CLI scripts.
- **Tests:** `t/*.t` run by `prove`, typically using `Test::More`.
- **Sinks to note:** backticks / `system` / `open "... |"`, `DBI` `do`/`prepare` with
  interpolation, `eval` of a string, `open` with untrusted paths, template `Text::...` with raw
  output.
