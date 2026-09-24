---
name: build-python
description: "Recipe for building a Python test environment in the sandbox."
---

# Building Python targets

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
