import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState, type ChangeEvent, type FormEvent } from "react";
import { mutations } from "@/api/queries";
import type { components } from "@/api/schema";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

type Finding = components["schemas"]["Finding"];
type RunState = components["schemas"]["RunState"];

const EMPTY = {
  title: "",
  repo_url: "",
  revision: "HEAD",
  source_mode: "git_revision" as Finding["source_mode"],
  description: "",
  cwe: "",
  file_path: "",
};

/** Optional fields are omitted when blank so the API applies its own defaults. */
function finding(draft: typeof EMPTY): Finding {
  return {
    title: draft.title.trim(),
    repo_url: draft.repo_url.trim(),
    revision: draft.revision.trim(),
    source_mode: draft.source_mode,
    description: draft.description,
    ...(draft.cwe.trim() ? { cwe: draft.cwe.trim() } : {}),
    ...(draft.file_path.trim() ? { file_path: draft.file_path.trim() } : {}),
  };
}

export function NewInvestigationForm({
  onCreated,
  onCancel,
}: {
  onCreated: (run: RunState) => void;
  onCancel: () => void;
}) {
  const client = useQueryClient();
  const [draft, setDraft] = useState(EMPTY);
  const submit = useMutation(mutations.submit(client));
  const set =
    (key: keyof typeof EMPTY) =>
    (
      event: ChangeEvent<
        HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement
      >,
    ) =>
      setDraft((current) => ({ ...current, [key]: event.target.value }));
  const onSubmit = (event: FormEvent) => {
    event.preventDefault();
    submit.mutate(finding(draft), {
      onSuccess: (run) => {
        setDraft(EMPTY);
        onCreated(run);
      },
    });
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>New investigation</CardTitle>
        <p className="text-sm text-muted-foreground">
          Submit a finding and a source revision. The investigator inspects the
          code, prepares its environment and tests the finding in an isolated
          OpenShell sandbox.
        </p>
      </CardHeader>
      <CardContent>
        <form onSubmit={onSubmit} className="grid gap-4">
          <label className="form-label">
            Finding title
            <input
              required
              maxLength={1000}
              className="field"
              value={draft.title}
              onChange={set("title")}
            />
          </label>
          <div className="grid gap-4 md:grid-cols-[3fr_1fr]">
            <label className="form-label">
              Repository URL or approved local path
              <input
                required
                className="field"
                value={draft.repo_url}
                onChange={set("repo_url")}
              />
            </label>
            <label className="form-label">
              Revision
              <input
                required
                className="field"
                value={draft.revision}
                onChange={set("revision")}
              />
            </label>
          </div>
          <div className="grid gap-4 md:grid-cols-3">
            <label className="form-label">
              Source
              <select
                className="field"
                value={draft.source_mode}
                onChange={set("source_mode")}
              >
                <option value="git_revision">Git revision</option>
                <option value="working_snapshot">Local working snapshot</option>
              </select>
            </label>
            <label className="form-label">
              CWE (optional)
              <input
                className="field"
                placeholder="CWE-78"
                value={draft.cwe}
                onChange={set("cwe")}
              />
            </label>
            <label className="form-label">
              File path (optional)
              <input
                className="field"
                placeholder="src/handler.py"
                value={draft.file_path}
                onChange={set("file_path")}
              />
            </label>
          </div>
          <label className="form-label">
            Finding description
            <textarea
              rows={4}
              className="field resize-y"
              value={draft.description}
              onChange={set("description")}
            />
          </label>
          {submit.error && (
            <p
              role="alert"
              className="rounded-md border border-destructive/40 bg-destructive/5 p-3 text-sm"
            >
              {submit.error.message}
            </p>
          )}
          <div className="flex flex-wrap gap-2">
            <Button type="submit" disabled={submit.isPending}>
              {submit.isPending ? "Submitting…" : "Start investigation"}
            </Button>
            <Button type="button" variant="outline" onClick={onCancel}>
              Close
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}
