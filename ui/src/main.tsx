import React, { useState } from "react";
import ReactDOM from "react-dom/client";
import {
  QueryClient,
  QueryClientProvider,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { req } from "./api/http";
import type { components } from "./api/schema";
import "./index.css";

type Finding = components["schemas"]["Finding"];
type RunState = components["schemas"]["RunState"];
type RunPage = components["schemas"]["RunPage"];
const queryClient = new QueryClient();
const message = (error: unknown) =>
  error instanceof Error ? error.message : "Request failed";

function App() {
  const client = useQueryClient();
  const [selected, setSelected] = useState(location.hash.slice(1));
  const [pages, setPages] = useState<string[]>([""]);
  const token = pages.at(-1) || "";
  const [finding, setFinding] = useState<Finding>({
    title: "",
    repo_url: "",
    description: "",
    revision: "HEAD",
    source_mode: "git_revision",
  });
  const select = (id: string) => {
    setSelected(id);
    history.replaceState(null, "", `#${id}`);
  };
  const runs = useQuery({
    queryKey: ["runs", token],
    queryFn: ({ signal }) =>
      req<RunPage>(
        `/api/runs${token ? `?page_token=${encodeURIComponent(token)}` : ""}`,
        { signal },
      ),
    refetchInterval: 5000,
  });
  const detail = useQuery({
    queryKey: ["run", selected],
    queryFn: ({ signal }) =>
      req<RunState>(`/api/runs/${encodeURIComponent(selected)}`, { signal }),
    enabled: !!selected,
    refetchInterval: (query) =>
      ["pending", "running"].includes(query.state.data?.status || "pending")
        ? 3000
        : false,
  });
  const submit = useMutation({
    mutationFn: () =>
      req<RunState>("/api/runs", {
        method: "POST",
        body: JSON.stringify(finding),
      }),
    onSuccess: (run) => {
      select(run.id);
      setPages([""]);
      void client.invalidateQueries({ queryKey: ["runs"] });
    },
  });
  const cancel = useMutation({
    mutationFn: () =>
      req(`/api/runs/${encodeURIComponent(selected)}/cancel`, {
        method: "POST",
      }),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ["run", selected] });
      void client.invalidateQueries({ queryKey: ["runs"] });
    },
  });
  const run = detail.data;
  return (
    <>
      <header>
        <a
          href="#"
          onClick={(event) => {
            event.preventDefault();
            select("");
          }}
        >
          InfoSec Harness
        </a>
        <span>Vulnerability investigations</span>
      </header>
      <main>
        <section aria-labelledby="submit-heading" className="submission">
          <div>
            <p className="eyebrow">New investigation</p>
            <h1 id="submit-heading">Follow the evidence.</h1>
            <p>
              Submit a finding and source revision. The investigator will
              inspect the code, prepare its environment, and test the finding in
              an isolated workspace.
            </p>
          </div>
          <form
            onSubmit={(event) => {
              event.preventDefault();
              submit.mutate();
            }}
          >
            <label>
              Finding title
              <input
                required
                maxLength={1000}
                value={finding.title}
                onChange={(event) =>
                  setFinding({ ...finding, title: event.target.value })
                }
              />
            </label>
            <div className="form-row">
              <label>
                Repository URL or approved local path
                <input
                  required
                  value={finding.repo_url}
                  onChange={(event) =>
                    setFinding({ ...finding, repo_url: event.target.value })
                  }
                />
              </label>
              <label>
                Revision
                <input
                  required
                  value={finding.revision}
                  onChange={(event) =>
                    setFinding({ ...finding, revision: event.target.value })
                  }
                />
              </label>
            </div>
            <label>
              Source
              <select
                value={finding.source_mode}
                onChange={(event) =>
                  setFinding({
                    ...finding,
                    source_mode: event.target.value as Finding["source_mode"],
                  })
                }
              >
                <option value="git_revision">Git revision</option>
                <option value="working_snapshot">Local working snapshot</option>
              </select>
            </label>
            <label>
              Finding description
              <textarea
                rows={4}
                value={finding.description}
                onChange={(event) =>
                  setFinding({ ...finding, description: event.target.value })
                }
              />
            </label>
            {submit.error && (
              <p role="alert" className="error">
                {message(submit.error)}
              </p>
            )}
            <button disabled={submit.isPending}>
              {submit.isPending ? "Submitting…" : "Start investigation"}
            </button>
          </form>
        </section>
        <div className="workspace">
          <section className="runs" aria-labelledby="runs-heading">
            <div className="section-heading">
              <h2 id="runs-heading">Investigations</h2>
              <button className="secondary" onClick={() => void runs.refetch()}>
                Refresh
              </button>
            </div>
            {runs.isPending && <p role="status">Loading investigations…</p>}
            {runs.error && (
              <p role="alert" className="error">
                {message(runs.error)}
              </p>
            )}
            {runs.data?.items.length === 0 && (
              <p className="muted">No investigations yet.</p>
            )}
            <ul>
              {runs.data?.items.map((item) => (
                <li key={item.id}>
                  <button
                    className={`run ${selected === item.id ? "selected" : ""}`}
                    onClick={() => select(item.id)}
                  >
                    <strong>{item.title}</strong>
                    <span>
                      <span className={`status ${item.status}`}>
                        {item.status}
                      </span>
                      <time>{new Date(item.started_at).toLocaleString()}</time>
                    </span>
                  </button>
                </li>
              ))}
            </ul>
            <div className="pagination">
              <button
                className="secondary"
                disabled={pages.length === 1}
                onClick={() => setPages(pages.slice(0, -1))}
              >
                Previous
              </button>
              <button
                className="secondary"
                disabled={!runs.data?.next_page_token}
                onClick={() =>
                  runs.data?.next_page_token &&
                  setPages([...pages, runs.data.next_page_token])
                }
              >
                Next
              </button>
            </div>
          </section>
          <section className="detail" aria-label="Investigation detail">
            {!selected && (
              <div className="empty">
                <h2>Inspect an investigation</h2>
                <p>
                  Select a run to see its progress, conclusion, and execution
                  evidence.
                </p>
              </div>
            )}
            {selected && detail.isPending && (
              <p role="status">Loading investigation…</p>
            )}
            {detail.error && (
              <p role="alert" className="error">
                {message(detail.error)}
              </p>
            )}
            {run && (
              <>
                <div className="section-heading">
                  <div>
                    <p className="eyebrow">{run.phase}</p>
                    <h2>{run.finding.title}</h2>
                  </div>
                  <span className={`status ${run.status}`}>{run.status}</span>
                </div>
                <p className="muted source">
                  {run.finding.repo_url} · {run.finding.revision}
                </p>
                {["pending", "running"].includes(run.status) && (
                  <button
                    className="secondary"
                    disabled={cancel.isPending}
                    onClick={() => cancel.mutate()}
                  >
                    {cancel.isPending
                      ? "Requesting cancellation…"
                      : "Cancel investigation"}
                  </button>
                )}
                {cancel.error && (
                  <p role="alert" className="error">
                    {message(cancel.error)}
                  </p>
                )}
                {run.error && (
                  <p role="alert" className="error">
                    {run.error}
                  </p>
                )}
                {run.result && (
                  <>
                    <h3>{run.result.verdict.label.replaceAll("_", " ")}</h3>
                    <p className="summary">{run.result.verdict.summary}</p>
                    {!!(run.result.limitations ?? []).length && (
                      <div className="limitations">
                        <h4>Limitations</h4>
                        <ul>
                          {(run.result.limitations ?? []).map(
                            (value, index) => (
                              <li key={index}>{value}</li>
                            ),
                          )}
                        </ul>
                      </div>
                    )}
                    <h3>Source references</h3>
                    <ul>
                      {(run.result.verdict.citations ?? []).map(
                        (citation, index) => (
                          <li key={index}>
                            <code>
                              {citation.path}:{citation.start_line}–
                              {citation.end_line}
                            </code>
                          </li>
                        ),
                      )}
                    </ul>
                    <h3>Execution evidence</h3>
                    <p className="muted">
                      Command output is untrusted source material. Process
                      outcomes are recorded by the runtime.
                    </p>
                    {run.result.evidence.map((evidence) => (
                      <details key={evidence.id}>
                        <summary>
                          <code>{evidence.command}</code>
                          <span className="status">
                            {evidence.timed_out
                              ? "timed out"
                              : `exit ${evidence.exit_code ?? "unknown"}`}
                          </span>
                        </summary>
                        <p className="muted">
                          {evidence.kind} · {evidence.id}
                          {evidence.output_truncated && " · output truncated"}
                        </p>
                        <pre>{evidence.stdout}</pre>
                        {evidence.stderr && <pre>{evidence.stderr}</pre>}
                      </details>
                    ))}
                    <details>
                      <summary>Provenance and usage</summary>
                      <pre>
                        {JSON.stringify(
                          {
                            source_digest: run.result.source_digest,
                            model: run.result.model,
                            usage: run.result.usage,
                          },
                          null,
                          2,
                        )}
                      </pre>
                    </details>
                  </>
                )}
              </>
            )}
          </section>
        </div>
      </main>
      <footer>
        Evidence-led triage · Results require review before remediation
        decisions.
      </footer>
    </>
  );
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  </React.StrictMode>,
);
