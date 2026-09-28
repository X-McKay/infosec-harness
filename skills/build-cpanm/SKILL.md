---
name: build-cpanm
description: Recipe for building a Perl test environment in the sandbox. Use this when planning or
  repairing a build for a cpanfile or Makefile.PL project.
metadata:
  owner: appsec
  version: 1.0.0
---

# Building Perl targets

<!-- generated: activation criteria (scripts/restructure_skills.py) -->

## Use this skill when

- You are producing or repairing an EnvironmentSpec for a Perl repository.
- The repository declares a cpanfile, Makefile.PL, or Build.PL.

## Do not use this skill when

- The repository is not Perl.

<!-- /generated: activation criteria -->

- **Base image:** `perl:5.40` (or the repo's pinned major).
- **Install:** `cpanm --notest --installdeps .` (reads `cpanfile`/`Makefile.PL`). Add
  `--mirror <url>` only to a mirror the repo declares. `cpanm App::prove` if `prove` is absent.
  For native deps, add the matching `-dev` system packages.
- **test_command:** `prove -v {test_file}` (`-v` so probe markers appear on stdout).
- **Partial builds:** install deps for and test a single module directory.

<!-- generated: constraints (scripts/restructure_skills.py) -->

## Safety constraints

- Install as the non-root sandbox user with `HOME=/work/home`; never `sudo` or run as root.
- Use only the package indexes and registries the repository itself declares.
- Build-time network access is limited to the registry allowlist; probe time has none at all.

## Completion criteria

- The spec names a base image from the allowlisted registries.
- Install commands come from the repository's own manifests.
- The test runner itself is installed, not merely assumed present.
- `test_command` contains the literal `{test_file}` placeholder — never a hardcoded test path. The harness writes the probe to the path its author chose and substitutes it here; a hardcoded path runs a file that does not exist and no test executes.

<!-- /generated: constraints -->
