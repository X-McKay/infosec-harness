import { req } from "@/api/http";
import {
  parseReportDocument,
  parseReportSummaries,
  reportApiPath,
  type ReportDocument,
  type ReportSummaries,
} from "@/lib/reports";

/** `GET /api/reports`: the newest report files first. */
export const reportsQuery = () => ({
  queryKey: ["reports"] as const,
  queryFn: async ({
    signal,
  }: {
    signal: AbortSignal;
  }): Promise<ReportSummaries> =>
    parseReportSummaries(await req<unknown>("/api/reports", { signal })),
  refetchInterval: 15_000,
});

export type LoadedReport = { raw: unknown; document: ReportDocument };

/** `GET /api/reports/{name}`; an invalid name is refused before any request. */
export const reportQuery = (name: string) => ({
  queryKey: ["report", name] as const,
  queryFn: async ({
    signal,
  }: {
    signal: AbortSignal;
  }): Promise<LoadedReport> => {
    const path = reportApiPath(name);
    if (!path) throw new Error("This report name is not valid.");
    const raw = await req<unknown>(path, { signal });
    return { raw, document: parseReportDocument(raw) };
  },
  // A completed report never changes; a running cohort is rewritten after every case.
  staleTime: Infinity,
  refetchInterval: (query: { state: { data?: LoadedReport } }) => {
    const document = query.state.data?.document;
    return document?.shape === "cohort" && document.report.status === "running"
      ? 5_000
      : false;
  },
});
