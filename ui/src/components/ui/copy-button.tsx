import { Check, Copy, X } from "lucide-react";
import { useEffect, useState } from "react";
import { cn } from "@/lib/utils";

type CopyState = "idle" | "copied" | "failed";

/**
 * Copies a value (often a full hash shown shortened) to the clipboard. The accessible name is
 * the fixed `label` ("Copy run ID"), never the value: recorded text is never an attribute. The
 * outcome is announced through a polite live region.
 */
export function CopyButton({
  value,
  label,
  className,
}: {
  value: string;
  label: string;
  className?: string;
}) {
  const [state, setState] = useState<CopyState>("idle");
  useEffect(() => {
    if (state === "idle") return;
    const timer = window.setTimeout(() => setState("idle"), 1500);
    return () => window.clearTimeout(timer);
  }, [state]);
  const Icon = state === "copied" ? Check : state === "failed" ? X : Copy;
  return (
    <span className="inline-flex items-center align-middle">
      <button
        type="button"
        aria-label={label}
        className={cn(
          "inline-flex h-6 w-6 shrink-0 items-center justify-center rounded text-muted-foreground transition-colors hover:bg-muted hover:text-foreground",
          state === "copied" && "text-emerald-700 dark:text-emerald-300",
          state === "failed" && "text-red-700 dark:text-red-300",
          className,
        )}
        onClick={async (event) => {
          event.stopPropagation();
          try {
            if (!navigator.clipboard) throw new Error("Clipboard unavailable");
            await navigator.clipboard.writeText(value);
            setState("copied");
          } catch {
            setState("failed");
          }
        }}
      >
        <Icon className="h-3.5 w-3.5" aria-hidden="true" />
      </button>
      <span className="sr-only" role="status" aria-live="polite">
        {state === "copied"
          ? "Copied"
          : state === "failed"
            ? "Copy failed"
            : ""}
      </span>
    </span>
  );
}
