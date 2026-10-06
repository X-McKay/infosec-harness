---
name: lang-javascript
description: 'Conventions for reading JavaScript and TypeScript repositories: npm layout, entry points,
  and Jest tests. Use this when the repository is primarily JS or TS.'
metadata:
  owner: appsec
  version: 1.1.0
---

# JavaScript / TypeScript repositories

## Use this skill when

- The repository's primary language is JavaScript or TypeScript.
- You need to locate its entry points, module resolution, or tests.

## Do not use this skill when

- The repository is primarily another language.
- You are planning the build itself — use `environment`.

## Procedure

- **Manifests:** `package.json` (`dependencies`, `scripts`, `workspaces`). Lockfiles:
  `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`. TS: `tsconfig.json`.
- **Layout:** `src/`, compiled `dist/`/`build/`. Monorepos use `packages/*` workspaces.
- **Entry points:** Express/Koa/Fastify route handlers, Next.js API routes, CLI `bin` scripts,
  React components rendering untrusted data.
- **Tests:** Jest/Vitest, files `*.test.js|ts` or under `__tests__/`.
- **Sinks to note:** `child_process.exec`, `eval`/`new Function`, `fs` with dynamic paths,
  `innerHTML`/`dangerouslySetInnerHTML`, string-built SQL, `fetch`/`axios` with dynamic URLs.

## Completion criteria

- You can name the manifest, the module system, the entry points, and where tests live.

