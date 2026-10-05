import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold",
  {
    variants: {
      variant: {
        default: "border-transparent bg-primary text-primary-foreground",
        outline: "text-foreground",
        exploitable:
          "border-transparent bg-red-500/15 text-red-700 dark:text-red-400",
        safe: "border-transparent bg-emerald-500/15 text-emerald-700 dark:text-emerald-400",
        inconclusive:
          "border-transparent bg-amber-500/15 text-amber-700 dark:text-amber-400",
      },
    },
    defaultVariants: { variant: "default" },
  },
);

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
