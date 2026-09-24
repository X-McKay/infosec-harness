---
name: lang-javascript
description: "Conventions for reading JS/TS repos: npm layout, entry points, and Jest tests."
---

# JavaScript / TypeScript repositories

- **Manifests:** `package.json` (`dependencies`, `scripts`, `workspaces`). Lockfiles:
  `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`. TS: `tsconfig.json`.
- **Layout:** `src/`, compiled `dist/`/`build/`. Monorepos use `packages/*` workspaces.
- **Entry points:** Express/Koa/Fastify route handlers, Next.js API routes, CLI `bin` scripts,
  React components rendering untrusted data.
- **Tests:** Jest/Vitest, files `*.test.js|ts` or under `__tests__/`.
- **Sinks to note:** `child_process.exec`, `eval`/`new Function`, `fs` with dynamic paths,
  `innerHTML`/`dangerouslySetInnerHTML`, string-built SQL, `fetch`/`axios` with dynamic URLs.
