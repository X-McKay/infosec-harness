---
name: build-npm
description: Recipe for building a Node, JavaScript or TypeScript test environment in the sandbox,
  for any of jest, vitest, mocha and node's own test runner. Use this when planning or repairing a
  build for a package.json project.
metadata:
  owner: appsec
  version: 1.0.0
---

# Building Node targets

## Use this skill when

- You are producing or repairing an EnvironmentSpec for a Node project.
- The repository declares a package.json.

## Do not use this skill when

- The repository is not a Node project.

## Procedure

- **Base image:** `node:22-slim` (match `engines.node` when pinned).
- **Install (use the lockfile's tool):**
  - `package-lock.json` -> `npm ci` (or `npm install` when no lockfile)
  - `pnpm-lock.yaml` -> `corepack enable && pnpm install --frozen-lockfile`
  - `yarn.lock` -> `corepack enable && yarn install --frozen-lockfile`
- **test_command — one form per runner, and they are not interchangeable.** Read the repo's
  `scripts.test` and `devDependencies` and take the runner it actually uses:

  | the project runs | test_command |
  | --- | --- |
  | jest | `npx jest --silent=false --runTestsByPath {test_file}` |
  | vitest | `npx vitest run --silent=false {test_file}` |
  | mocha | `npx mocha {test_file}` |
  | node's own runner (`node --test`) | `node --test {test_file}` |

  - **`--silent=false` is not optional for jest or vitest.** A repository `jest.config.js` or
    `vitest.config.js` carrying `silent: true` — an ordinary thing for a project with chatty
    tests — replaces the test's console, so **all three `HARNESS_` markers vanish and the run
    still exits 0**. Measured on both runners under node 22: the probe is correct, the exit
    status says success, and the harness records that nothing reached the sink. The flag
    overrides the config and does nothing when the project silences nothing, so carry it always.
    mocha and node's runner never capture a test's stdout and need no flag.
  - **Match the selector to the runner.** `--runTestsByPath` is jest's; vitest takes a bare path
    and dies in its own argument parser on that flag, before loading a single test file. When a
    repository carries both — a migration in progress leaves jest and vitest side by side in
    `devDependencies` — take the one its own `test` script invokes. `npx <runner>` cannot rescue
    a runner the project does not have: the probe container is offline and npx exits with
    `npx canceled due to missing packages` and no test output at all.
  - **TypeScript needs more than "install ts-jest".** A bare `npx jest` on a `.ts` probe fails to
    parse it: the default babel transform has no TypeScript plugin. Measured, in order of least
    work: **vitest** compiles TS with no configuration; `npx tsx --test {test_file}` does the same
    for node's runner; jest needs ts-jest named on the command line
    (`npx jest --preset ts-jest --silent=false --runTestsByPath {test_file}`, since the spec may
    not edit the repo's jest.config) **and** the type declarations for the test globals —
    `@types/jest` and `@types/node` — because ts-jest type-checks the probe and stops with
    `TS2582: Cannot find name 'test'`, reporting `Tests: 0 total` without running anything.
  - **ESM and `.mjs`:** a jest probe cannot `import` from a `"type": "module"` package unless the
    command sets `NODE_OPTIONS=--experimental-vm-modules`; without it the suite dies on `Cannot
    use import statement outside a module`. A probe written as `.mjs` is worse: jest's default
    `testMatch` does not include `.mjs`, so even `--runTestsByPath` reports `No tests found`.
    vitest and node's runner handle both natively.
- **Registries:** honor `.npmrc`/`.yarnrc.yml` registries and scopes the repo declares; pass
  auth tokens as BuildKit secrets.
- **Partial builds:** install and test within one workspace package dir.

## Safety constraints

- Install as the non-root sandbox user with `HOME=/work/home`; never `sudo` or run as root.
- Use only the package indexes and registries the repository itself declares.
- Build-time network access is limited to the registry allowlist; probe time has none at all.

## Completion criteria

- The spec names a base image from the allowlisted registries.
- Install commands come from the repository's own manifests.
- The test runner itself is installed, not merely assumed present.
- No install command swallows its own failure (`|| true`, `|| :`, `; true`). A dependency install that reports success when it failed surfaces only at probe time, where probe repair cannot fix it and build repair never sees it.
- `test_command` contains the literal `{test_file}` placeholder — never a hardcoded test path. The harness writes the probe to the path its author chose and substitutes it here; a hardcoded path runs a file that does not exist and no test executes.
- A jest or vitest `test_command` carries `--silent=false`. A repository `jest.config.js` or `vitest.config.js` that sets `silent: true` replaces the test's console, so all three `HARNESS_` markers disappear while the run still exits 0 — a correct probe recorded as having reached nothing, with nothing in the output to say why. mocha and `node --test` never capture a test's stdout and need no flag.
- `test_command` invokes the runner the repository's own `test` script invokes, with the selector that runner accepts: `--runTestsByPath` is jest's and vitest rejects it outright. `npx` cannot rescue a runner the project does not declare — the probe container is offline, so it exits with `npx canceled due to missing packages` and no test output at all.
- A TypeScript probe runs under a runner that compiles TypeScript: vitest or `npx tsx --test` need no configuration, while jest needs `--preset ts-jest` *and* `@types/jest` installed, because ts-jest type-checks the probe and stops on `TS2582: Cannot find name 'test'`.

