import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { number } from "@/lib/format";

export type Distribution = {
  count: number;
  population: number;
  coverage: number | null;
  mean?: number | null;
  p50?: number | null;
  p95?: number | null;
  maximum?: number | null;
  bins?: Array<{ lower: number; upper: number; count: number }>;
};

type Props = {
  title: string;
  data: Distribution;
  binHref?: (index: number) => string;
  unit?: string;
  format?: (value: number | null | undefined) => string;
};

export function DistributionChart({
  title,
  data,
  format = number,
  binHref,
  unit = "value range",
}: Props) {
  const bins = data.bins ?? [];
  const maxCount = Math.max(1, ...bins.map((bin) => bin.count));
  const maximum = data.maximum ?? bins.at(-1)?.upper ?? null;
  const coverage =
    data.coverage == null
      ? "Coverage unavailable"
      : `${number(data.coverage * 100)}% coverage`;

  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        <p className="text-xs text-muted-foreground">
          {number(data.count, 0)} of {number(data.population, 0)} measured ·{" "}
          {coverage}
        </p>
      </CardHeader>
      <CardContent>
        <div className="mb-5 flex flex-wrap justify-between gap-2 text-sm">
          <span>
            Mean <strong>{format(data.mean)}</strong>
          </span>
          <span className="text-muted-foreground">
            p50 {format(data.p50)} · p95 {format(data.p95)}
          </span>
        </div>
        {data.count > 0 && bins.length > 0 ? (
          <>
            <svg
              viewBox="0 0 520 178"
              role="img"
              aria-label={`${title} distribution; median ${format(data.p50)}, 95th percentile ${format(data.p95)}`}
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
              <line
                x1="48"
                y1="130"
                x2="500"
                y2="130"
                stroke="currentColor"
                className="text-border"
              />
              {bins.map((bin, index) => {
                const height = (bin.count / maxCount) * 100;
                const bar = (
                  <rect
                    x={52 + index * (440 / bins.length)}
                    y={130 - height}
                    width={Math.max(1, 440 / bins.length - 4)}
                    height={height}
                    rx="3"
                    className="fill-primary/75"
                  >
                    <title>
                      {format(bin.lower)}–{format(bin.upper)}:{" "}
                      {number(bin.count, 0)} runs
                    </title>
                  </rect>
                );
                return binHref ? (
                  <a
                    key={index}
                    href={binHref(index)}
                    aria-label={`Show ${bin.count} runs in ${format(bin.lower)}–${format(bin.upper)}`}
                  >
                    {bar}
                  </a>
                ) : (
                  <g key={index}>{bar}</g>
                );
              })}
              {[data.p50, data.p95].map((value, index) =>
                value == null ? null : (
                  <line
                    key={`quantile-${index}`}
                    x1={52 + (value / (bins.at(-1)?.upper || 1)) * 440}
                    x2={52 + (value / (bins.at(-1)?.upper || 1)) * 440}
                    y1="22"
                    y2="130"
                    stroke="currentColor"
                    strokeDasharray={index ? "2 3" : "6 3"}
                    className="text-foreground"
                  >
                    <title>
                      {index ? "p95" : "p50"}: {format(value)}
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
                {format(bins[0]?.lower)}
              </text>
              <text
                x="500"
                y="153"
                textAnchor="end"
                fontSize="10"
                fill="currentColor"
                className="text-muted-foreground"
              >
                {format(maximum)}
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
                runs
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
                      Runs
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {bins.map((bin, index) => (
                    <tr key={`${bin.lower}-${bin.upper}-${index}`}>
                      <td>
                        {binHref ? (
                          <a
                            className="underline underline-offset-2"
                            href={binHref(index)}
                          >
                            {format(bin.lower)}–{format(bin.upper)}
                          </a>
                        ) : (
                          `${format(bin.lower)}–${format(bin.upper)}`
                        )}
                      </td>
                      <td className="text-right">{number(bin.count, 0)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </details>
          </>
        ) : (
          <p className="flex h-44 items-center justify-center text-sm text-muted-foreground">
            No measured observations in this cohort.
          </p>
        )}
      </CardContent>
    </Card>
  );
}
