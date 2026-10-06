import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

/**
 * Two badge families that never share a shape:
 * - verdicts (exploitable, safe, inconclusive) are filled, fully rounded pills;
 * - states (lifecycle, gate and check states, tags) are outlined with squarer corners, and
 *   `muted` (not checked, unknown, not cited) is dashed so it never reads as a pass.
 * Text colours are the 800 shades in light mode and 300 in dark mode for WCAG AA on the tints.
 */
const badgeVariants = cva(
  "inline-flex items-center whitespace-nowrap border px-2 py-0.5 text-xs font-semibold leading-4",
  {
    variants: {
      variant: {
        // Verdict family: filled pills.
        exploitable:
          "rounded-full border-transparent bg-red-500/15 px-2.5 text-red-800 dark:bg-red-500/20 dark:text-red-300",
        safe: "rounded-full border-transparent bg-emerald-500/15 px-2.5 text-emerald-800 dark:bg-emerald-500/20 dark:text-emerald-300",
        inconclusive:
          "rounded-full border-transparent bg-amber-500/15 px-2.5 text-amber-800 dark:bg-amber-500/20 dark:text-amber-300",
        // State family: outlined, squarer.
        default:
          "rounded-md border-transparent bg-primary text-primary-foreground",
        outline: "rounded-md text-foreground",
        active:
          "rounded-md border-primary/50 bg-primary/10 text-primary dark:border-primary/60",
        passed:
          "rounded-md border-emerald-600/50 text-emerald-800 dark:border-emerald-400/50 dark:text-emerald-300",
        failed:
          "rounded-md border-red-600/50 text-red-800 dark:border-red-400/50 dark:text-red-300",
        warning:
          "rounded-md border-amber-600/50 text-amber-800 dark:border-amber-400/50 dark:text-amber-300",
        muted: "rounded-md border-dashed font-medium text-muted-foreground",
      },
    },
    defaultVariants: { variant: "default" },
  },
);

export type BadgeVariant = NonNullable<
  VariantProps<typeof badgeVariants>["variant"]
>;

/** Inline (span) so a badge is valid inside headings, labels and table cells. */
export function Badge({
  className,
  variant,
  ...props
}: React.HTMLAttributes<HTMLSpanElement> & VariantProps<typeof badgeVariants>) {
  return (
    <span className={cn(badgeVariants({ variant }), className)} {...props} />
  );
}
