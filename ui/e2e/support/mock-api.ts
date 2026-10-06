/**
 * A synthetic `/api/*` served from the JSON fixtures in e2e/fixtures/. Every mocked test
 * routes `**\/api/**` here, so the default suite never reaches a real API. Requests are
 * recorded so tests can assert what the UI sent (for example a POST body).
 */
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { Page, Request, Route } from "@playwright/test";

const fixtureRoot = fileURLToPath(new URL("../fixtures/", import.meta.url));
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

/** Parsed fixture by path relative to e2e/fixtures/; undefined when absent. */
export function fixture<T = unknown>(relative: string): T | undefined {
  const path = `${fixtureRoot}${relative}`;
  return existsSync(path)
    ? (JSON.parse(readFileSync(path, "utf8")) as T)
    : undefined;
}

export type Recorded = {
  method: string;
  path: string;
  search: string;
  body: unknown;
};
export type Reply = { status?: number; body?: unknown; delayMs?: number };
type Handler = (request: Request, url: URL) => Reply | Promise<Reply>;

const notFound = (detail = "Not found"): Reply => ({
  status: 404,
  body: { detail },
});

export const NEW_RUN_ID = "investigate-v11-new-0099";
/** Report files the API lists but cannot parse; the detail endpoint answers 422. */
const UNREADABLE = new Set(["legacy-broken.json"]);

export class MockApi {
  readonly requests: Recorded[] = [];
  private readonly overrides: {
    method: string;
    path: RegExp;
    handler: Handler;
  }[] = [];
  private submitted: Record<string, unknown> | null = null;

  constructor(private readonly page: Page) {}

  async install() {
    await this.page.route("**/api/**", (route) => this.handle(route));
  }

  /** Replace the default answer for one method and path pattern; the newest override wins. */
  on(method: string, path: RegExp, handler: Handler | Reply) {
    this.overrides.unshift({
      method: method.toUpperCase(),
      path,
      handler: typeof handler === "function" ? handler : () => handler,
    });
  }

  /** Requests whose method and pathname match. */
  calls(method: string, path: string | RegExp): Recorded[] {
    return this.requests.filter(
      (call) =>
        call.method === method.toUpperCase() &&
        (typeof path === "string" ? call.path === path : path.test(call.path)),
    );
  }

  private async handle(route: Route) {
    const request = route.request();
    const url = new URL(request.url());
    let body: unknown = request.postData();
    try {
      body = body == null ? null : JSON.parse(body as string);
    } catch {
      // keep the raw text
    }
    this.requests.push({
      method: request.method(),
      path: url.pathname,
      search: url.search,
      body,
    });
    const override = this.overrides.find(
      (item) =>
        item.method === request.method() && item.path.test(url.pathname),
    );
    const reply = override
      ? await override.handler(request, url)
      : this.answer(request.method(), url, body);
    if (reply.delayMs)
      await new Promise((resolve) => setTimeout(resolve, reply.delayMs));
    await route.fulfill({
      status: reply.status ?? 200,
      contentType: "application/json",
      body: JSON.stringify(reply.body ?? null),
    });
  }

  private answer(method: string, url: URL, body: unknown): Reply {
    const path = url.pathname;
    const segments = path.split("/").filter(Boolean).map(decodeURIComponent);
    if (method === "GET" && path === "/api/health")
      return { body: fixture("health.json") };
    if (path === "/api/runs") {
      if (method === "POST") return this.submit(body);
      if (method === "GET") {
        const token = url.searchParams.get("page_token");
        if (!token) return { body: fixture("runs-page-1.json") };
        if (token === "tok-page-2")
          return { body: fixture("runs-page-2.json") };
        return { status: 400, body: { detail: "Invalid page token" } };
      }
    }
    if (segments[0] === "api" && segments[1] === "runs" && segments[2]) {
      const id = segments[2];
      if (!SAFE_NAME.test(id)) return notFound("Investigation not found");
      if (segments.length === 3 && method === "GET") {
        if (id === NEW_RUN_ID && this.submitted)
          return {
            body: {
              id,
              status: "pending",
              phase: "queued",
              finding: this.submitted,
              result: null,
              error: null,
            },
          };
        const run = fixture(`runs/${id}.json`);
        return run ? { body: run } : notFound("Investigation not found");
      }
      if (segments[3] === "events" && method === "GET") {
        const events = fixture(`events/${id}.json`);
        return events ? { body: events } : notFound("Investigation not found");
      }
      if (segments[3] === "cancel" && method === "POST")
        return { status: 202, body: { status: "cancellation_requested" } };
    }
    if (method === "GET" && path === "/api/reports")
      return { body: fixture("reports-index.json") };
    if (method === "GET" && segments[1] === "reports" && segments[2]) {
      const name = segments[2];
      if (!SAFE_NAME.test(name)) return notFound("Report not found");
      if (UNREADABLE.has(name))
        return {
          status: 422,
          body: { detail: "Report is not a readable JSON object" },
        };
      const report = fixture(`reports/${name}`);
      return report ? { body: report } : notFound("Report not found");
    }
    return notFound();
  }

  private submit(body: unknown): Reply {
    const finding = (body ?? {}) as Record<string, unknown>;
    this.submitted = finding;
    return {
      status: 202,
      body: { id: NEW_RUN_ID, status: "pending", phase: "queued", finding },
    };
  }
}
