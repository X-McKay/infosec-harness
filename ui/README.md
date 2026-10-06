# UI

A React + TypeScript single-page app built with Vite, TanStack Router and Query, and
Tailwind with shadcn-style components (Radix slot, class-variance-authority, lucide icons).
It submits findings, lists this generation's investigations, shows one investigation's
verdict, the evidence behind it and its limitations, and reads the cohort evaluation,
qualification and replay reports the harness recorded. It holds no state of its own: every
view is a projection of Temporal state or of a report file, served by
`src/infosec_harness/api.py`. The only browser storage is the appearance preference.

## Routes

| Path | View | Refresh |
| --- | --- | --- |
| `/` | Investigations: new-investigation form, status tiles, search, status and verdict filters, paginated list with click-through | 5 s |
| `/runs/$runId` | Investigation: status and phase, verdict with cited evidence and source citations, limitations, evidence cards by kind, event timeline (Temporal bookkeeping hidden behind a toggle), the recorded failure type of a failed run, model, worker identity and usage, cancellation | 3 s while pending or running |
| `/reports` | Reports: every report file newest first, filterable by kind (`?kind=`), with status, commit and model, completed of planned, task success, unsafe negatives and gate states | 15 s |
| `/reports/$name` | Report: a cohort or diagnostic evaluation (provenance, release gates, capacity pre-flight, distributions, language and CWE breakdowns, vulnerable/fixed pairs, cases filterable by `?case=&outcome=&language=`, failures, operation estimate), a qualification or a replay by its shape, and the raw document; anything else as a JSON tree | 5 s while a cohort is unfinished |
| `/metrics` | Metrics: task success, unsafe negatives, completion and median duration across the 20 newest full-corpus cohorts | 15 s |
| `/qualification` | Qualification: the newest native OpenShell qualification report | 15 s |
| `/runtime` | Runtime: API health, generation, task queue, API base and appearance | 30 s |

List filters and the current page token live in the URL (`?q=&status=&verdict=&page=`), so a
detail page links back to the same list view and steps to its neighbors; the report-kind and
case-table filters do the same. Each route validator owns its keys (`ownedSearch` in
`src/lib/search.ts`): TanStack Router merges validated search over the raw query, so a rejected
value such as `?status=bogus` is reset rather than applied. The API offers no server-side
filtering, so search and filters apply to the loaded page; the list says so.

Keyboard: on the list, `/` focuses the search box (ArrowDown leaves it for the first row),
`j`/`k` move between rows (the arrow keys, Home and End too once a row has focus) and Enter
opens the focused row; on an investigation opened from the list, `j`/`k` open the next and
previous one. Shortcuts never fire while typing in a field or with a modifier held.

Every view that polls shows a Live indicator with its interval ("Live · every 5 s"), which turns
to Retrying when a refresh fails and the last known data stays on screen; a finished
investigation or report shows only when it was loaded. Run IDs, evidence and sandbox IDs,
digests, worker identity hashes and the shortened hashes in reports have copy buttons that copy
the full recorded value.

Below 768px the sidebar becomes a compact header: brand, runtime summary (its details behind a
disclosure) and appearance on one row, and the navigation as one horizontally scrolling row
that keeps the current route in view. The investigations table then keeps the Investigation and
Elapsed columns, with status, verdict and start time inside each row.

`$name` must match `^[A-Za-z0-9][A-Za-z0-9._-]*\.json$` (at most 255 characters, the API's own
rule) before the report view renders or any request is made; anything else is not found.
Evaluation views build links only from validated report names and workflow IDs, through
`EvaluationLinkProvider`, which `main.tsx` fills with a TanStack Router `Link`.

A cohort report is rewritten after every case and stamped `finished_at` only at its end; a
mid-run case failure already records `status: failed`. A report without `finished_at`, without
a recorded abort and with cases pending is shown as not finished, its figures as partial, and
it refreshes. Diagnostic subsets (`diagnostic-*`) never qualify; Metrics excludes them.

## Endpoints

All requests go through `req()` in `src/api/http.ts` to same-origin `/api/*` paths, and all of
them are declared in `src/api/queries.ts`:

| Call | Response schema | Used by |
| --- | --- | --- |
| `GET /api/health` | `Health` (also the 503 body when Temporal is unreachable) | sidebar indicator, Runtime |
| `GET /api/runs?page_token=` | `RunPage` of `RunSummary` | Investigations, detail neighbors |
| `POST /api/runs` | `RunState` | new-investigation form |
| `GET /api/runs/{id}` | `RunState` | Investigation |
| `POST /api/runs/{id}/cancel` | status object | Investigation, after confirmation |
| `GET /api/runs/{id}/events` | `RunEvents` of `RunEvent` | Investigation timeline and failure type; hidden when the API answers 404 |
| `GET /api/reports` | `ReportList` of `ReportSummary` | Reports, Metrics, Qualification |
| `GET /api/reports/{name}` | JSON object (untyped) | Report, Metrics, Qualification |

The API bounds what it serves: 50 runs per page (a verdict only when the completed result was
read in time), at most 500 history events per run (`truncated` beyond that) as a kind, activity
name and a 200-character label such as an exit code or failure type, never payloads or failure
messages; the newest 200 top-level `*.json` files in `reports_dir` (`truncated` beyond that,
the list says so), with a file it cannot parse listed as `unreadable`; one report of at most
16 MiB (404 outside `reports_dir`, 413 when larger, 422 when not a JSON object).

Types come from `components["schemas"]` in the generated `src/api/schema.d.ts`. The full
report documents (`CohortReport`, `QualificationReport`, `ReplayReport` in `src/lib/reports.ts`)
are hand-typed because the API serves them as an untyped object; their parsers turn a missing
or malformed field into null and any gate state other than `passed` or `failed` into
`not_checked`. Responses typed by the schema are still narrowed (`normalizeEvents`,
`healthPresentation`, `parseReportSummaries`): their labels are untrusted text.

## Files

| Path | Role |
| --- | --- |
| `src/main.tsx` | Router, sidebar shell, navigation, evaluation link provider and query client |
| `src/api/http.ts` | `req()` and `ApiError`, which turns API errors into short display messages |
| `src/api/queries.ts` | Every `/api` call, query keys, refresh and retry policy, mutations |
| `src/api/schema.d.ts` | Generated client types; never edit by hand |
| `src/routes/Investigations.tsx` | List view |
| `src/routes/InvestigationDetail.tsx` | Detail view |
| `src/routes/Reports.tsx` | Report list |
| `src/routes/ReportDetail.tsx` | One report, rendered by its shape |
| `src/routes/Metrics.tsx` | Cross-cohort trends |
| `src/routes/Qualification.tsx` | Newest native qualification |
| `src/routes/Runtime.tsx` | Runtime view |
| `src/components/investigations/` | Submission form, verdict and limitations, evidence card, timeline, identity and usage |
| `src/components/evaluations/` | Cohort, qualification and replay report views, case table, failures, charts (`CaseHistogram`, `SeriesChart`), JSON tree, shared badges and tables, and `links.tsx` (`EvaluationLinkProvider`) |
| `src/components/ui/` | `badge`, `button`, `card`, `table` primitives, `copy-button` and `breakable` (wrap names and paths at separators) |
| `src/components/QueryState.tsx` | Loading and error states, and `Freshness` with the live indicator |
| `src/components/RuntimeIndicator.tsx` | Shell health summary (sidebar, or phone header with a disclosure) |
| `src/components/ThemeProvider.tsx` | System, light or dark appearance |
| `src/lib/status.ts` | Run status groups, activity and badges for both status vocabularies |
| `src/lib/verdict.ts` | Verdict labels, badges and what each label requires |
| `src/lib/provenance.ts` | Probe claims, harness source checks and probe completeness |
| `src/lib/search.ts` | Route search state (list, report kind, case filters), filtering and neighbors |
| `src/lib/keyboard.ts` | List and detail shortcut rules |
| `src/lib/events.ts` | Event narrowing, bookkeeping and failure labels |
| `src/lib/runtime.ts` | Health presentation |
| `src/lib/workflow.ts` | Elapsed time, status counts and phase labels |
| `src/lib/reports.ts` | Report listing and document parsers, report name and workflow ID validation |
| `src/lib/evaluation.ts` | Cohort measures mirroring `evals/cohort.py`: success over planned cases, unsafe negatives, percentiles, breakdowns, pairs, failure classes, capacity reading, unfinished cohorts |
| `src/lib/format.ts`, `json.ts`, `theme.ts`, `utils.ts` | Formatting (including line counts and shortened locations), JSON narrowing, appearance and `cn()` |
| `src/index.css` | Tailwind layers and the light and dark design tokens |

## Rules

Finding text, probe output, model output, event labels and report content are untrusted.
Render them only as React text: never with `dangerouslySetInnerHTML`, never as link targets and
never as attribute values (DOM ids for evidence cards come from their position). The only
untrusted values that become link targets are report names and workflow IDs, and only after
`isReportName` or `isWorkflowId` accepts them. Command output is
shown in bounded, wrapped `.output` blocks and only while expanded.

A displayed exit code or recorded value is not execution evidence on its own. Probe claims are
parsed from the probe's own output and recorded with `origin: self_reported`; the evidence card
says so, separates them from the harness's source verification and workspace digest, and lists
any gaps against the complete, source-verified probe rule. Every report shows its limitations,
and a report without limitations says that absence is not evidence. Anything the API does not
report is shown as not reported or not checked, never as passed or zero, and `not_checked` is
drawn as a dashed, muted badge that never shares the passed styling.

Badges come in two families that never share a shape. Verdicts (and case outcomes, which judge
a verdict) are filled, fully rounded pills. Lifecycle, gate and check states are outlined with
squarer corners: passed green, failed red, in flight in the primary colour, warnings amber, and
not checked, unknown or not started dashed and neutral. A copy button's accessible name is a
fixed label ("Copy run ID"), never the value it copies.

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

## End-to-end tests

Playwright specs in `e2e/` drive the production bundle (`npm run build`, then `vite preview`
on `127.0.0.1:4173`) in Chromium, as three projects: `desktop` (1280×800), `dark` (dark color
scheme) and `mobile` (Pixel 7). Every default test answers `/api/*` from the synthetic JSON
fixtures in `e2e/fixtures/` (`e2e/support/mock-api.ts`), freezes the clock at
2026-10-05 12:00 UTC, and fails on any console error, uncaught page error or request that
leaves the preview origin. No default test reaches a real API.

Besides the per-feature specs, `routes.spec.ts` checks every route for one h1, named controls
and no horizontal page scroll; `shell.spec.ts` the phone header and sidebar layouts;
`interaction.spec.ts` keyboard navigation, copy buttons (with clipboard permission), URL
filters and the live indicator; and `contrast.spec.ts` WCAG AA text contrast on every route in
the light and dark projects, measuring each text run against its composited background
(`e2e/support/contrast.ts`).

```bash
npx playwright install chromium   # once; downloads into the user's Playwright cache
npm run e2e                       # type-check e2e/, then every project
npm run e2e -- --project desktop run-detail # a subset; any Playwright arguments
npm run e2e:ui                    # interactive runner
E2E_REUSE_SERVER=1 npm run e2e    # reuse a preview already serving this build on 4173
E2E_LIVE_API_URL=http://127.0.0.1:8000 npm run e2e -- --project desktop live-smoke
```

`just ui-e2e` runs the same from the repository root. The live smoke spec is skipped unless
`E2E_LIVE_API_URL` is set; it forwards only GET requests to that API (list, one run, reports,
health) and aborts anything else. Report fixtures come from `e2e/fixtures/generate-reports.mjs`;
edit and rerun it rather than the JSON. A test that exposes a UI defect stays in the suite as
`test.fixme` with the defect in its annotation until the UI is fixed. The HTML report is written
to `playwright-report/` and failure artifacts to `test-results/` (both ignored).

## Deployment

The `Dockerfile` pins Node and nginx by version and index digest. `nginx.conf` proxies `/api/`
to the API, falls back to `index.html` for client routes, and sets a same-origin
Content-Security-Policy (no inline styles or scripts), `nosniff`, `frame-ancestors 'none'` and
`no-store` for `/api/` and `index.html` at server level, so no location drops them; hashed
`/assets/` are cached as immutable. `dist/`, `node_modules/` and `*.tsbuildinfo` are ignored.
