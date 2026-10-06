# UI

A React + TypeScript single-page app built with Vite, TanStack Router and Query, and
Tailwind with shadcn-style components (Radix slot, class-variance-authority, lucide icons).
It submits findings, lists this generation's investigations and shows one investigation's
verdict, the evidence behind it and its limitations. It holds no state of its own: every view
is a projection of Temporal state served by `src/infosec_harness/api.py`. The only browser
storage is the appearance preference.

## Routes

| Path | View | Refresh |
| --- | --- | --- |
| `/` | Investigations: new-investigation form, status tiles, search, status and verdict filters, paginated list with click-through | 5 s |
| `/runs/$runId` | Investigation: status and phase, verdict with cited evidence and source citations, limitations, evidence cards by kind, event timeline, model, worker identity and usage, cancellation | 3 s while pending or running |
| `/runtime` | Runtime: API health, generation, task queue, API base and appearance | 30 s |
| `/reports`, `/qualification` | Placeholders (see below) | none |

List filters and the current page token live in the URL (`?q=&status=&verdict=&page=`), so a
detail page links back to the same list view and steps to its neighbors. The API offers no
server-side filtering, so search and filters apply to the loaded page; the list says so.
Press `/` on the list to focus the search box.

## Endpoints

All requests go through `req()` in `src/api/http.ts` to same-origin `/api/*` paths, and all of
them are declared in `src/api/queries.ts`:

| Call | Used by |
| --- | --- |
| `GET /api/health` | sidebar indicator, Runtime |
| `GET /api/runs?page_token=` | Investigations, detail neighbors |
| `POST /api/runs` | new-investigation form |
| `GET /api/runs/{id}` | Investigation |
| `POST /api/runs/{id}/cancel` | Investigation, after confirmation |
| `GET /api/runs/{id}/events` | Investigation timeline; hidden when the API answers 404 |

`RunSummary.verdict`, `cwe` and `repo_url` and the health fields `temporal` and `task_queue`
are shown when the API reports them and omitted otherwise. The events response is typed by
hand in `src/lib/events.ts` until it is in `openapi.json`; after `just regenerate`, replace
that interface with the generated schema type.

## Files

| Path | Role |
| --- | --- |
| `src/main.tsx` | Router, sidebar shell, navigation and query client |
| `src/api/http.ts` | `req()` and `ApiError`, which turns API errors into short display messages |
| `src/api/queries.ts` | Every `/api` call, query keys, refresh and retry policy, mutations |
| `src/api/schema.d.ts` | Generated client types; never edit by hand |
| `src/routes/Investigations.tsx` | List view |
| `src/routes/InvestigationDetail.tsx` | Detail view |
| `src/routes/Runtime.tsx` | Runtime view |
| `src/routes/placeholders.tsx` | Placeholder Reports and Qualification views |
| `src/components/investigations/` | Submission form, verdict and limitations, evidence card, timeline, identity and usage |
| `src/components/ui/` | `badge`, `button`, `card`, `table` primitives |
| `src/components/QueryState.tsx` | Loading, error and freshness states |
| `src/components/RuntimeIndicator.tsx` | Sidebar health summary |
| `src/components/ThemeProvider.tsx` | System, light or dark appearance |
| `src/components/DistributionChart.tsx` | Histogram card with an accessible data table |
| `src/lib/status.ts` | Run status groups, activity and badges for both status vocabularies |
| `src/lib/verdict.ts` | Verdict labels, badges and what each label requires |
| `src/lib/provenance.ts` | Probe claims, harness source checks and probe completeness |
| `src/lib/search.ts` | List route state, filtering and neighbors |
| `src/lib/events.ts` | Hand-typed events response and its narrowing |
| `src/lib/runtime.ts` | Health presentation |
| `src/lib/workflow.ts` | Elapsed time, status counts and phase labels |
| `src/lib/format.ts`, `json.ts`, `theme.ts`, `utils.ts` | Formatting, JSON narrowing, appearance and `cn()` |
| `src/index.css` | Tailwind layers and the light and dark design tokens |

### Reserved for the reports and qualification views

Another change owns these and the integrator fills them in; this tree does not contain them:
`src/routes/Reports*.tsx`, `src/routes/Qualification.tsx`, `src/components/evaluations/*`
and `src/lib/evaluation.ts`. The integrator replaces the two placeholder components in
`src/routes/placeholders.tsx` and their routes in `src/main.tsx`; the sidebar already links to
`/reports` and `/qualification`.

## Rules

Finding text, probe output, model output and report content are untrusted. Render them only
as React text: never with `dangerouslySetInnerHTML`, never as link targets and never as
attribute values (DOM ids for evidence cards come from their position). Command output is
shown in bounded, wrapped `.output` blocks and only while expanded.

A displayed exit code or recorded value is not execution evidence on its own. Probe claims are
parsed from the probe's own output and recorded with `origin: self_reported`; the evidence card
says so, separates them from the harness's source verification and workspace digest, and lists
any gaps against the complete, source-verified probe rule. Every report shows its limitations,
and a report without limitations says that absence is not evidence. Anything the API does not
report is shown as not reported or not checked, never as passed.

Make no network calls except `/api/*` through `req()`. Use `components["schemas"]` types for
everything the generated schema covers.

## Development

Use `./dev` from the repository root for the managed stack. For frontend work against a
separately running API, run from this directory (Node >= 22.6):

```bash
npm ci
npm run dev          # localhost:8080; /api proxies to VITE_API_URL (default localhost:8000)
npm run format:check # prettier over src/, including tests
npm test             # node:test unit tests next to their modules (also run by prebuild)
npm run build        # tests, TypeScript checks (app and tests) and production bundle
npm run check:api    # fails if src/api/schema.d.ts differs from openapi.json; writes nothing
```

From the repository root, `just regenerate` rewrites `openapi.json` from the API and
`src/api/schema.d.ts` from that document; commit both together. `just ui-check` runs the
formatting, client drift and build checks that CI runs.

Tests are `*.test.ts` files next to the module they cover, run by
`node --experimental-strip-types --test` and type-checked by `tsconfig.test.json`. Node runs
the sources without a bundler, so modules under `src/lib/` and `src/api/` use relative imports
with a `.ts` extension for anything imported at runtime; the `@/` alias resolves only in Vite
and TypeScript. Type-only imports are erased and may omit the extension. Avoid TypeScript-only
runtime syntax (enums, namespaces, parameter properties) in those modules.

## Deployment

The `Dockerfile` pins Node and nginx by version and index digest. `nginx.conf` proxies `/api/`
to the API, falls back to `index.html` for client routes, and sets a same-origin
Content-Security-Policy (no inline styles or scripts), `nosniff`, `frame-ancestors 'none'` and
`no-store` for `/api/` and `index.html` at server level, so no location drops them; hashed
`/assets/` are cached as immutable. `dist/`, `node_modules/` and `*.tsbuildinfo` are ignored.
