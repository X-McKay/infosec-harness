# UI

React + TypeScript with Vite, Radix/Tailwind components and TanStack Router/Query.
Use `./dev` from the repository root for the managed stack with hot reload and allocated ports.

For frontend work against a separately running API, run from this directory (Node >= 22.6):

```bash
npm ci
npm run dev          # localhost:8080; /api proxies to localhost:8000
npm run format:check # prettier over src/, including tests
npm test             # node:test unit tests (also run by prebuild)
npm run build        # tests, TypeScript checks (app and tests) and production bundle
npm run check:api    # fails if src/api/schema.d.ts differs from openapi.json; writes nothing
```

Set `VITE_API_URL` to change the development API proxy target. `src/routes/` contains views,
`src/components/` reusable UI, `src/lib/` search and shared helpers, and `src/api/` API access.
The interface includes triage, finding evidence/review, metrics, experiments and configuration.

## API contract

From the repository root, `just openapi` regenerates `openapi.json` from FastAPI and
`src/api/schema.d.ts` from that document. Commit both together; do not edit the generated
TypeScript directly. Use `components["schemas"][...]` aliases (exported from
`src/api/client.ts`) rather than hand-written response types. `just generated-check` checks
backend schema drift; `npm run check:api` and CI check client drift.

`src/api/client.ts` is the only place that sets the record population: every read requests
`population=operational`, overriding any caller value. Route state, query keys and views do
not carry a population. Query options, polling policy and mutations live in
`src/api/queries.ts`; runs, batches and evaluations each have one activity helper in
`src/lib/status.ts`.

## Tests

Tests are `*.test.ts` files next to the module they cover, run directly by
`node --experimental-strip-types --test`. They are type-checked by `tsconfig.test.json` (which
adds Node types) and formatted by prettier. Because Node runs the TypeScript sources without a
bundler, modules under `src/lib/` and `src/api/` must use relative imports with a `.ts`
extension for anything imported at runtime (`import { x } from "./json.ts"`); the `@/` alias
only resolves in Vite and TypeScript. Type-only imports are erased and may omit the
extension. These modules must also avoid TypeScript-only runtime syntax (enums, namespaces,
parameter properties), which type stripping does not support.

## Rendering and deployment

Finding text, probe output and model output are untrusted: render them as React text, never
with `dangerouslySetInnerHTML` or as link targets. Recorded or configured values are not
execution evidence; the evidence-basis notice warns unless every recorded execution origin is
controller-authored.

The `Dockerfile` pins Node and nginx by version and index digest. `nginx.conf` serves the
bundle with gzip, a same-origin Content-Security-Policy, `X-Content-Type-Options`,
`frame-ancestors 'none'` and `no-store` for `/api/` and `index.html`; hashed `/assets/` are
cached as immutable. Headers are set once at server level through a cache-control map, because
a location-level `add_header` would drop the inherited security headers.

`dist/`, `node_modules/` and TypeScript build caches are local outputs ignored by Git.
The build cache lives in `node_modules/.cache/`. See the
[repository guide](../docs/development/REPOSITORY_GUIDE.md) for other output locations.
