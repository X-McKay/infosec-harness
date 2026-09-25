# InfoSec Harness — Web

React + TypeScript (Vite) triage UI built with shadcn-style components (Radix + Tailwind),
TanStack Router / Query / Table. The API client types are generated from the backend's
OpenAPI document.

```bash
npm install
npm run gen:api      # regenerate src/api/schema.d.ts from openapi.json
npm run dev          # http://localhost:8080 (proxies /api -> http://localhost:8000)
npm run build
```

Regenerate `openapi.json` from the backend with:
`uv run python -c "import json,infosec_harness.api.app as a; open('web/openapi.json','w').write(json.dumps(a.app.openapi(),indent=2))"`

Views: triage queue (filter by verdict, priority-sorted), finding detail (verdict,
agent-cost trace, review/override, raw finding + result), experiments, and configuration.
