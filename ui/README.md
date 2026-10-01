# UI

React + TypeScript with Vite, Radix/Tailwind components and TanStack Router/Query/Table.
Use `./dev` from the repository root for the managed stack with hot reload and allocated ports.

For frontend work against a separately running API, run from this directory:

```bash
npm ci
npm run dev          # localhost:8080; /api proxies to localhost:8000
npm run format:check
npm run build       # search tests, TypeScript checks and production bundle
```

Set `VITE_API_URL` to change the development API proxy target. `src/routes/` contains views,
`src/components/` reusable UI, `src/lib/` search and shared helpers, and `src/api/` API access.
The interface includes triage, finding evidence/review, metrics, experiments and configuration.

From the repository root, `just openapi` regenerates `openapi.json` from FastAPI and
`src/api/schema.d.ts` from that document. Commit both together; do not edit the generated
TypeScript directly. `just generated-check` checks backend schema drift, and CI checks client drift.

`dist/`, `node_modules/` and TypeScript build caches are local outputs ignored by Git.
The build cache lives in `node_modules/.cache/`. See the
[repository guide](../docs/development/REPOSITORY_GUIDE.md) for other output locations.
