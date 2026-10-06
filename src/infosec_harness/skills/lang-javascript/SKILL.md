---
name: lang-javascript
description: 'JavaScript and TypeScript repositories: npm layout, entry points, tests. Use this when the repository is primarily JS or TS.'
metadata:
  owner: appsec
  version: 1.2.0
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

## When the toolchain is absent

The workspace image ships `node` and `npm`; Jest, Vitest and other packages come from the
repository's declared dependencies through `environment`. Verify with `command -v node npm`
and, for a runner, its binary under `node_modules/.bin`. A probe needs no runner: a plain
`node` script that loads the real module and prints the `HARNESS_PROBE` line is enough. If a
package the target cannot load without is missing and `environment` cannot provide it, do not
stub it. Return `inconclusive`, name the exact missing tool or package as a limitation in the
verdict summary, and record what reading established.

## Completion criteria

- You can name the manifest, the module system, the entry points, and where tests live.

