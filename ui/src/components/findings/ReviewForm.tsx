import { timestamp } from "@/lib/format";
import type { RunDetail } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { verdictLabel } from "@/lib/verdict";

export const REVIEW_VERDICTS = [
  "potentially_exploitable",
  "inconclusive",
  "likely_not_exploitable",
] as const;
export type ReviewVerdict = (typeof REVIEW_VERDICTS)[number];

type ReviewFormProps = {
  run: RunDetail;
  reviewer: string;
  setReviewer: (value: string) => void;
  decision: string;
  setDecision: (value: string) => void;
  overrideLabel: ReviewVerdict;
  setOverrideLabel: (value: ReviewVerdict) => void;
  reason: string;
  setReason: (value: string) => void;
  saving: boolean;
  error: Error | null;
  onSave: () => void;
};

export function ReviewForm({
  run,
  reviewer,
  setReviewer,
  decision,
  setDecision,
  overrideLabel,
  setOverrideLabel,
  reason,
  setReason,
  saving,
  error,
  onSave,
}: ReviewFormProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Analyst review</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-3 sm:grid-cols-2">
          <label className="text-sm">
            Reviewer
            <input
              className="field mt-1 w-full"
              value={reviewer}
              onChange={(event) => setReviewer(event.target.value)}
              placeholder="Name or team"
            />
          </label>
          <label className="text-sm">
            Decision
            <select
              className="field mt-1 w-full"
              value={decision}
              onChange={(event) => setDecision(event.target.value)}
            >
              <option value="confirm">Confirm recorded verdict</option>
              <option value="override">Override verdict</option>
            </select>
          </label>
        </div>
        {decision === "override" && (
          <label className="block text-sm">
            Override verdict
            <select
              className="field mt-1 w-full"
              value={overrideLabel}
              onChange={(event) =>
                setOverrideLabel(event.target.value as ReviewVerdict)
              }
            >
              {REVIEW_VERDICTS.map((value) => (
                <option key={value} value={value}>
                  {verdictLabel(value)}
                </option>
              ))}
            </select>
          </label>
        )}
        <label className="block text-sm">
          Reason
          <textarea
            className="field mt-1 min-h-20 w-full"
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            placeholder="Explain the evidence for this review"
          />
        </label>
        {error != null && (
          <p role="alert" className="text-sm text-destructive">
            Could not save review: {error.message}
          </p>
        )}
        <Button
          disabled={
            saving ||
            !reviewer.trim() ||
            (decision === "override" && !reason.trim())
          }
          onClick={onSave}
        >
          {saving ? "Saving…" : "Save review"}
        </Button>
        {run.review && (
          <div className="rounded-md border bg-muted/30 p-3 text-sm">
            <p>
              <strong>Current review:</strong>{" "}
              {run.review.reviewer || "Unnamed reviewer"} ·{" "}
              {run.review.decision}
              {run.review.override_label
                ? ` → ${verdictLabel(run.review.override_label)}`
                : ""}
            </p>
            <p className="mt-1 text-muted-foreground">
              {run.review.reason || "No reason recorded."}
            </p>
          </div>
        )}
        {run.review_history?.length > 0 && (
          <div>
            <p className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
              Review history
            </p>
            <div className="space-y-2">
              {run.review_history.map((entry, index) => (
                <div
                  key={`${entry.created_at}-${index}`}
                  className="border-l-2 pl-3 text-sm"
                >
                  <p>
                    {entry.reviewer || "Unnamed reviewer"} · {entry.decision}
                    {entry.override_label
                      ? ` → ${verdictLabel(String(entry.override_label))}`
                      : ""}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    {entry.reason || "No reason recorded."} ·{" "}
                    {timestamp(entry.created_at)}
                  </p>
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
