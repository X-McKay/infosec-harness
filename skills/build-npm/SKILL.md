---
name: build-npm
description: "Recipe for building a Node/JS test environment in the sandbox."
---

# Building Node targets

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
