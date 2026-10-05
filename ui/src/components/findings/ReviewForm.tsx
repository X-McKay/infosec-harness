import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import type { RunDetail, VerdictLabel } from "@/api/client";
import { mutations } from "@/api/queries";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { timestamp } from "@/lib/format";
import { VERDICT_LABELS, verdictLabel } from "@/lib/verdict";

// The API accepts exactly these decisions (see the backend review endpoint).
type ReviewDecision = "confirm" | "override";

/** Render with key={run.id}: draft and save state belong to one finding. */
export function ReviewForm({ run }: { run: RunDetail }) {
  const queryClient = useQueryClient();
  const review = useMutation(mutations.review(queryClient, run.id));
  const [reviewer, setReviewer] = useState("");
  const [decision, setDecision] = useState<ReviewDecision>("confirm");
  const [overrideLabel, setOverrideLabel] = useState<VerdictLabel>(
    VERDICT_LABELS[0],
  );
  const [reason, setReason] = useState("");
  const save = () =>
    review.mutate(
      {
        reviewer: reviewer.trim(),
        decision,
        reason,
        override_label: decision === "override" ? overrideLabel : null,
      },
      { onSuccess: () => setReason("") },
    );
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
              onChange={(event) =>
                setDecision(event.target.value as ReviewDecision)
              }
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
                setOverrideLabel(event.target.value as VerdictLabel)
              }
            >
              {VERDICT_LABELS.map((value) => (
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
        {review.isError && (
          <p role="alert" className="text-sm text-destructive">
            Could not save review: {review.error.message}
          </p>
        )}
        <Button
          disabled={
            review.isPending ||
            !reviewer.trim() ||
            (decision === "override" && !reason.trim())
          }
          onClick={save}
        >
          {review.isPending ? "Saving…" : "Save review"}
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
        {run.review_history.length > 0 && (
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
                      ? ` → ${verdictLabel(entry.override_label)}`
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
