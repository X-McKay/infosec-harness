---
name: build-cpanm
description: "Recipe for building a Perl test environment in the sandbox."
---

# Building Perl targets

- **Base image:** `perl:5.40` (or the repo's pinned major).
- **Install:** `cpanm --notest --installdeps .` (reads `cpanfile`/`Makefile.PL`). Add
  `--mirror <url>` only to a mirror the repo declares. `cpanm App::prove` if `prove` is absent.
  For native deps, add the matching `-dev` system packages.
- **test_command:** `prove -v {test_file}` (`-v` so probe markers appear on stdout).
- **Partial builds:** install deps for and test a single module directory.
