# UI

A single-page React + TypeScript app built with Vite and TanStack Query. It submits a finding,
lists this generation's investigations and shows one investigation's verdict, limitations,
source references and execution evidence. It holds no state of its own: every view is a
projection of Temporal state served by `src/infosec_harness/api.py`.

| File | Role |
| --- | --- |
| `src/main.tsx` | The whole interface: submission form, paginated run list, run detail and cancellation |
| `src/api/http.ts` | `req()` fetch wrapper and `ApiError`, which turns API errors into short display messages |
| `src/api/schema.d.ts` | Generated client types; never edit by hand |
| `src/index.css` | Styles |

It calls `GET /api/runs` (paged by `page_token`), `POST /api/runs`, `GET /api/runs/{id}` and
`POST /api/runs/{id}/cancel`. The list refreshes every 5 s and an open run every 3 s while it
is pending or running.

Use `./dev` from the repository root for the managed stack. For frontend work against a
separately running API, run from this directory (Node >= 22.6):

```bash
npm ci
npm run dev          # localhost:8080; /api proxies to VITE_API_URL (default localhost:8000)
npm run format:check # prettier over src/
npm test             # node:test unit tests next to their modules (also run by prebuild)
npm run build        # tests, TypeScript checks and production bundle
npm run check:api    # fails if src/api/schema.d.ts differs from openapi.json; writes nothing
```

From the repository root, `just regenerate` rewrites `openapi.json` from the API and
`src/api/schema.d.ts` from that document; commit both together. Use `components["schemas"]`
types rather than hand-written response types. `just ui-check` runs the formatting, client
drift and build checks that CI runs.

Finding text, probe output and model output are untrusted: render them as React text, never
with `dangerouslySetInnerHTML` or as link targets. A displayed exit code or recorded value is
not execution evidence on its own; the report's limitations say what was not established.

The `Dockerfile` pins Node and nginx by version and index digest. `nginx.conf` proxies `/api/`
to the API and sets a same-origin Content-Security-Policy, `nosniff`, `frame-ancestors 'none'`
and `no-store` for `/api/` and `index.html` at server level, so no location drops them; hashed
`/assets/` are cached as immutable. `dist/`, `node_modules/` and `*.tsbuildinfo` are ignored.
