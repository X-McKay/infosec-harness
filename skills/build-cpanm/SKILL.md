---
name: build-cpanm
description: Recipe for building a Perl test environment in the sandbox. Use this when planning or
  repairing a build for a cpanfile or Makefile.PL project.
metadata:
  owner: appsec
  version: 1.0.0
---

# Building Perl targets

## Use this skill when

- You are producing or repairing an EnvironmentSpec for a Perl repository.
- The repository declares a cpanfile, Makefile.PL, or Build.PL.

## Do not use this skill when

- The repository is not Perl.



## Safety constraints

- Install as the non-root sandbox user with `HOME=/work/home`; never `sudo` or run as root.
- Use only the package indexes and registries the repository itself declares.
- Build-time network access is limited to the registry allowlist; probe time has none at all.

## Completion criteria

- The spec names a base image from the allowlisted registries.
- Install commands come from the repository's own manifests.
- `test_command` contains the `{test_file}` placeholder and runs a single test file.
- The test runner itself is installed, not merely assumed present.
