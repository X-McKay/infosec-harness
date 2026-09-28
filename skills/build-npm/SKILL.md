---
name: build-npm
description: Recipe for building a Node and JavaScript test environment in the sandbox. Use this when
  planning or repairing a build for a package.json project.
metadata:
  owner: appsec
  version: 1.0.0
---

# Building Node targets

<!-- generated: activation criteria (scripts/restructure_skills.py) -->

## Use this skill when

- You are producing or repairing an EnvironmentSpec for a Node project.
- The repository declares a package.json.

## Do not use this skill when

- The repository is not a Node project.

<!-- /generated: activation criteria -->

- **Base image:** `node:22-slim` (match `engines.node` when pinned).
- **Install (use the lockfile's tool):**
  - `package-lock.json` -> `npm ci` (or `npm install` when no lockfile)
  - `pnpm-lock.yaml` -> `corepack enable && pnpm install --frozen-lockfile`
  - `yarn.lock` -> `corepack enable && yarn install --frozen-lockfile`
  - TypeScript projects: ensure `ts-jest`/`ts-node` or a build step so the probe can import.
- **test_command:** `npx jest --runTestsByPath {test_file}` (or `npx vitest run {test_file}`).
  Add `--silent=false` equivalents so probe stdout survives.
- **Registries:** honor `.npmrc`/`.yarnrc.yml` registries and scopes the repo declares; pass
  auth tokens as BuildKit secrets.
- **Partial builds:** install and test within one workspace package dir.

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
