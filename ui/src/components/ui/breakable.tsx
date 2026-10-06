import { Fragment } from "react";

/**
 * A file name, path or identifier that may wrap after its separators ("model-" / "2026…Z.json",
 * ".../eval-corpus/" / "perl/cmdi") instead of mid-token: line breaking never breaks after a
 * hyphen that precedes a digit, and not at all after "/". Plain text segments with <wbr>;
 * nothing becomes markup or an attribute. Pair with `[overflow-wrap:anywhere]` where a single
 * segment can still be wider than its box.
 */
export function Breakable({ children }: { children: string }) {
  const parts = children.split(/(?<=[-_/])/);
  return (
    <>
      {parts.map((part, index) => (
        <Fragment key={index}>
          {index > 0 && <wbr />}
          {part}
        </Fragment>
      ))}
    </>
  );
}
