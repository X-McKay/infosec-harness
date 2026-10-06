import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { histogram, percentile } from "@/lib/evaluation";
import { integer, number, percent } from "@/lib/format";

type Format = (value: number | null | undefined) => string;

/**
 * Per-case distribution in the DistributionChart visual language (same card, axes, bar
 * marks, p50/p90 rules and accessible table), computed from report case records rather than
 * an API distribution. A case without the measurement is reported in coverage, never as zero.
 */
export function CaseHistogram({
  title,
  values,
  population,
  format = number,
  unit = "value range",
  note,
  bins: binCount = 10,
}: {
  title: string;
  values: number[];
  population: number;
  format?: Format;
  unit?: string;
  note?: string;
  bins?: number;
}) {
  const bins = histogram(values, binCount);
  const maxCount = Math.max(1, ...bins.map((bin) => bin.count));
  const p50 = percentile(values, 0.5);
  const p90 = percentile(values, 0.9);
  const mean = values.length
    ? values.reduce((total, value) => total + value, 0) / values.length
    : null;
  const low = bins[0]?.lower ?? 0;
  const high = bins.at(-1)?.upper ?? 0;
  const position = (value: number) =>
    52 + (high === low ? 0.5 : (value - low) / (high - low)) * 440;
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        <p className="text-xs text-muted-foreground">
          {integer(values.length)} of {integer(population)} cases measured ·{" "}
          {population
            ? `${percent(values.length / population)} coverage`
            : "Coverage unavailable"}
        </p>
      </CardHeader>
      <CardContent>
        <div className="mb-5 flex flex-wrap justify-between gap-2 text-sm">
          <span>
            Mean <strong>{format(mean)}</strong>
          </span>
          <span className="text-muted-foreground">
            p50 {format(p50)} · p90 {format(p90)}
          </span>
        </div>
        {bins.length > 0 ? (
          <>
            <svg
              viewBox="0 0 520 178"
              role="img"
              aria-label={`${title} distribution; median ${format(p50)}, 90th percentile ${format(p90)}`}
              className="h-44 w-full overflow-visible"
            >
              {[0, 0.5, 1].map((fraction) => (
                <g key={fraction}>
                  <line
                    x1="48"
                    y1={130 - fraction * 100}
                    x2="500"
                    y2={130 - fraction * 100}
                    stroke="currentColor"
                    className="text-border"
                  />
                  <text
                    x="42"
                    y={134 - fraction * 100}
                    textAnchor="end"
                    fontSize="10"
                    fill="currentColor"
                    className="text-muted-foreground"
                  >
                    {Math.round(maxCount * fraction)}
                  </text>
                </g>
              ))}
              {bins.map((bin, index) => {
                const height = (bin.count / maxCount) * 100;
                const width = 440 / bins.length;
                return (
                  <rect
                    key={index}
                    x={52 + index * width}
                    y={130 - height}
                    width={Math.max(1, width - 4)}
                    height={height}
                    rx="3"
                    className="fill-primary/75"
                  >
                    <title>
                      {format(bin.lower)}–{format(bin.upper)}:{" "}
                      {integer(bin.count)} cases
                    </title>
                  </rect>
                );
              })}
              {[p50, p90].map((value, index) =>
                value == null ? null : (
                  <line
                    key={`quantile-${index}`}
                    x1={position(value)}
                    x2={position(value)}
                    y1="22"
                    y2="130"
                    stroke="currentColor"
                    strokeDasharray={index ? "2 3" : "6 3"}
                    className="text-foreground"
                  >
                    <title>
                      {index ? "p90" : "p50"}: {format(value)}
                    </title>
                  </line>
                ),
              )}
              <text
                x="48"
                y="153"
                fontSize="10"
                fill="currentColor"
                className="text-muted-foreground"
              >
                {format(low)}
              </text>
              <text
                x="500"
                y="153"
                textAnchor="end"
                fontSize="10"
                fill="currentColor"
                className="text-muted-foreground"
              >
                {format(high)}
              </text>
              <text
                x="274"
                y="173"
                textAnchor="middle"
                fontSize="10"
                fill="currentColor"
                className="text-muted-foreground"
              >
                {unit}
              </text>
              <text
                x="10"
                y="80"
                textAnchor="middle"
                transform="rotate(-90 10 80)"
                fontSize="10"
                fill="currentColor"
                className="text-muted-foreground"
              >
                cases
              </text>
            </svg>
            <details className="mt-3 text-xs">
              <summary className="cursor-pointer text-muted-foreground">
                View accessible distribution table
              </summary>
              <table
                className="mt-3 w-full"
                aria-label={`${title} histogram data`}
              >
                <caption className="sr-only">
                  {title} histogram bins; the final bin includes its upper edge
                </caption>
                <thead>
                  <tr>
                    <th scope="col" className="text-left">
                      Range
                    </th>
                    <th scope="col" className="text-right">
                      Cases
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {bins.map((bin, index) => (
                    <tr key={index}>
                      <td>
                        {format(bin.lower)}–{format(bin.upper)}
                      </td>
                      <td className="text-right">{integer(bin.count)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </details>
          </>
        ) : (
          <p className="flex h-44 items-center justify-center text-sm text-muted-foreground">
            No measured observations in this report.
          </p>
        )}
        {note && <p className="mt-3 text-xs text-muted-foreground">{note}</p>}
      </CardContent>
    </Card>
  );
}

export type SeriesPoint = {
  key: string;
  label: string;
  value: number | null;
  /** Optional lighter column behind the value, e.g. planned behind completed. */
  total?: number | null;
  tone?: "good" | "bad" | "muted";
};

/**
 * One column per report, oldest on the left. A missing value leaves an explicit gap marked
 * "n/a" rather than a zero-height bar.
 */
export function SeriesChart({
  title,
  description,
  points,
  format = number,
  maximum,
  reference,
}: {
  title: string;
  description?: string;
  points: SeriesPoint[];
  format?: Format;
  maximum?: number;
  reference?: { value: number; label: string } | null;
}) {
  const ceiling = Math.max(
    maximum ?? 0,
    reference?.value ?? 0,
    ...points.map((point) => Math.max(point.value ?? 0, point.total ?? 0)),
    1e-9,
  );
  const slot = 440 / Math.max(1, points.length);
  const y = (value: number) => 130 - (value / ceiling) * 100;
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        {description && (
          <p className="text-xs text-muted-foreground">{description}</p>
        )}
      </CardHeader>
      <CardContent>
        {points.length ? (
          <>
            <svg
              viewBox="0 0 520 160"
              role="img"
              aria-label={`${title} for ${points.length} reports, oldest first`}
              className="h-40 w-full overflow-visible"
            >
              {[0, 0.5, 1].map((fraction) => (
                <g key={fraction}>
                  <line
                    x1="48"
                    y1={130 - fraction * 100}
                    x2="500"
                    y2={130 - fraction * 100}
                    stroke="currentColor"
                    className="text-border"
                  />
                  <text
                    x="42"
                    y={134 - fraction * 100}
                    textAnchor="end"
                    fontSize="10"
                    fill="currentColor"
                    className="text-muted-foreground"
                  >
                    {format(ceiling * fraction)}
                  </text>
                </g>
              ))}
              {points.map((point, index) => {
                const width = Math.max(2, Math.min(36, slot - 6));
                const x = 52 + index * slot + (slot - width) / 2;
                return (
                  <g key={point.key}>
                    {point.total != null && (
                      <rect
                        x={x}
                        y={y(point.total)}
                        width={width}
                        height={130 - y(point.total)}
                        rx="3"
                        className="fill-muted-foreground/20"
                      />
                    )}
                    {point.value == null ? (
                      <text
                        x={x + width / 2}
                        y="126"
                        textAnchor="middle"
                        fontSize="9"
                        fill="currentColor"
                        className="text-muted-foreground"
                      >
                        n/a
                      </text>
                    ) : (
                      <rect
                        x={x}
                        y={y(point.value)}
                        width={width}
                        height={Math.max(
                          point.value ? 1 : 0,
                          130 - y(point.value),
                        )}
                        rx="3"
                        className={
                          point.tone === "bad"
                            ? "fill-red-500/70"
                            : point.tone === "muted"
                              ? "fill-muted-foreground/50"
                              : "fill-primary/75"
                        }
                      />
                    )}
                    <rect
                      x={x}
                      y="20"
                      width={width}
                      height="110"
                      fill="transparent"
                    >
                      <title>
                        {point.label}: {format(point.value)}
                        {point.total != null
                          ? ` of ${format(point.total)}`
                          : ""}
                      </title>
                    </rect>
                  </g>
                );
              })}
              {reference && (
                <g>
                  <line
                    x1="48"
                    x2="500"
                    y1={y(reference.value)}
                    y2={y(reference.value)}
                    stroke="currentColor"
                    strokeDasharray="6 3"
                    className="text-foreground"
                  />
                  <text
                    x="500"
                    y={y(reference.value) - 4}
                    textAnchor="end"
                    fontSize="10"
                    fill="currentColor"
                    className="text-foreground"
                  >
                    {reference.label}
                  </text>
                </g>
              )}
              <text
                x="52"
                y="150"
                fontSize="10"
                fill="currentColor"
                className="text-muted-foreground"
              >
                oldest
              </text>
              <text
                x="500"
                y="150"
                textAnchor="end"
                fontSize="10"
                fill="currentColor"
                className="text-muted-foreground"
              >
                newest
              </text>
            </svg>
            <details className="mt-3 text-xs">
              <summary className="cursor-pointer text-muted-foreground">
                View data table
              </summary>
              <table className="mt-3 w-full" aria-label={`${title} data`}>
                <thead>
                  <tr>
                    <th scope="col" className="text-left">
                      Report
                    </th>
                    <th scope="col" className="text-right">
                      Value
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {points.map((point) => (
                    <tr key={point.key}>
                      <td className="break-all">{point.label}</td>
                      <td className="text-right tabular-nums">
                        {format(point.value)}
                        {point.total != null ? ` / ${format(point.total)}` : ""}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </details>
          </>
        ) : (
          <p className="flex h-40 items-center justify-center text-sm text-muted-foreground">
            No cohort reports to compare yet.
          </p>
        )}
      </CardContent>
    </Card>
  );
}

/** A horizontal rate bar with its fraction as text; the text carries the value. */
export function RateBar({
  correct,
  planned,
}: {
  correct: number;
  planned: number;
}) {
  const rate = planned ? correct / planned : 0;
  return (
    <div className="flex min-w-[9rem] items-center gap-2">
      <div
        className="h-2 flex-1 overflow-hidden rounded-full bg-muted"
        aria-hidden
      >
        <div
          className="h-full rounded-full bg-primary/75"
          style={{ width: `${rate * 100}%` }}
        />
      </div>
      <span className="w-20 text-right tabular-nums text-xs">
        {correct}/{planned} · {planned ? percent(rate, 0) : "—"}
      </span>
    </div>
  );
}
