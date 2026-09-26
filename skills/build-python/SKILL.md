---
name: build-python
description: Recipe for building a Python test environment in the sandbox. Use this when planning
  or repairing a build for a pip, poetry, or uv project.
metadata:
  owner: appsec
  version: 1.0.0
---

# Building Python targets

## Use this skill when

- You are producing or repairing an EnvironmentSpec for a Python repository.
- The repository declares requirements.txt, pyproject.toml, setup.py, or a Pipfile.

## Do not use this skill when

- The repository is not Python.
- You are reading code rather than planning a build — use `lang-python`.



## Safety constraints

- Install as the non-root sandbox user with `HOME=/work/home`; never `sudo` or run as root.
- Use only the package indexes and registries the repository itself declares.
- Build-time network access is limited to the registry allowlist; probe time has none at all.

## Completion criteria

- The spec names a base image from the allowlisted registries.
- Install commands come from the repository's own manifests.
- `test_command` contains the `{test_file}` placeholder and runs a single test file.
- The test runner itself is installed, not merely assumed present.
