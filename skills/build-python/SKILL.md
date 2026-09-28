---
name: build-python
description: Recipe for building a Python test environment in the sandbox. Use this when planning
  or repairing a build for a pip, poetry, or uv project.
metadata:
  owner: appsec
  version: 1.0.0
---

# Building Python targets

<!-- generated: activation criteria (scripts/restructure_skills.py) -->

## Use this skill when

- You are producing or repairing an EnvironmentSpec for a Python repository.
- The repository declares requirements.txt, pyproject.toml, setup.py, or a Pipfile.

## Do not use this skill when

- The repository is not Python.
- You are reading code rather than planning a build — use `lang-python`.

<!-- /generated: activation criteria -->

- **Base image:** `python:3.12-slim` (match the repo's declared version when it pins one).
- **System packages:** add build/runtime libs only when a wheel needs them (e.g. `gcc`,
  `libpq-dev`, `libffi-dev`).
- **Install (as non-root, `HOME=/work/home`, using the repo's own indexes):**
  - `requirements.txt`: `python -m pip install --no-cache-dir --user -r requirements.txt`
  - poetry: `pip install --user poetry && poetry install --no-root` (or export to requirements)
  - uv: `pip install --user uv && uv sync --frozen`
  - installable package: `python -m pip install --no-cache-dir --user -e .`
  - always ensure the test runner: `python -m pip install --no-cache-dir --user pytest`
  - put `/work/home/.local/bin` on `PATH`.
- **test_command:** `python -m pytest -q -s {test_file}` (`-s` so probe stdout markers are not
  captured away). For `unittest`: `python -m pytest -q -s {test_file}` still runs it.
- Registries: honor `pip.conf` / `[tool.uv]`/`[tool.pip]` index settings the repo declares.

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
- The pytest command disables output capture with `-s`, or the probe's markers are buffered away and a correct probe is recorded as having reached nothing.

<!-- /generated: constraints -->
