import { useEffect, useRef, useState } from "react";
import { categoryLabel } from "../categories";
import type { DailyCount, ProtectionHistory as History } from "../types";

/*
 * "How much has this done for us?" — aggregates only. Effectiveness is shown
 * as what was checked and caught; we deliberately make no claim about money
 * saved or a catch rate, since misses can't be measured from here.
 */

const CHART_HEIGHT = 180;
const AXIS_GUTTER = 28; // left space for y-axis labels
const BAR_GAP = 3;

function formatDay(isoDate: string, options: Intl.DateTimeFormatOptions = { month: "short", day: "numeric" }) {
  // Dates are UTC calendar days; format in UTC so they don't shift a day.
  return new Date(`${isoDate}T00:00:00Z`).toLocaleDateString(undefined, { ...options, timeZone: "UTC" });
}

function niceMax(value: number): number {
  if (value <= 5) return 5;
  const step = value <= 20 ? 5 : 10;
  return Math.ceil(value / step) * step;
}

/** A bar with 4px-rounded top corners and a square base, per the chart mark spec. */
function topRoundedBar(x: number, y: number, width: number, height: number): string {
  const r = Math.min(4, width / 2, height);
  return `M${x},${y + height} V${y + r} Q${x},${y} ${x + r},${y} H${x + width - r} Q${x + width},${y} ${x + width},${y + r} V${y + height} Z`;
}

/** Keep the tooltip inside the panel: anchor it left/right near the chart edges. */
function tooltipAlign(index: number, count: number): "start" | "center" | "end" {
  if (index < count * 0.2) return "start";
  if (index > count * 0.8) return "end";
  return "center";
}

function ImpactTiles({ history }: { history: History }) {
  const tiles = [
    { value: history.emails_checked, label: "Emails checked", hint: `last ${history.days} days` },
    { value: history.threats_caught, label: "Threats caught", hint: "flagged for review" },
    { value: history.high_risk, label: "High-risk", hint: "scored 8–10, needed urgent attention" },
    { value: history.links_flagged, label: "Dangerous links", hint: "in flagged messages" },
  ];
  return (
    <div className="impact-tiles">
      {tiles.map((tile) => (
        <div key={tile.label} className="impact-tile">
          <span className="impact-tile__value">{tile.value.toLocaleString()}</span>
          <span className="impact-tile__label">{tile.label}</span>
          <span className="impact-tile__hint">{tile.hint}</span>
        </div>
      ))}
    </div>
  );
}

/** Track an element's rendered width so the SVG is drawn at 1:1 scale and text stays legible on phones. */
function useElementWidth<T extends HTMLElement>(fallback: number) {
  const ref = useRef<T>(null);
  const [width, setWidth] = useState(fallback);
  useEffect(() => {
    const element = ref.current;
    if (!element) return;
    const observer = new ResizeObserver(([entry]) => setWidth(Math.max(240, Math.round(entry.contentRect.width))));
    observer.observe(element);
    return () => observer.disconnect();
  }, []);
  return [ref, width] as const;
}

function DailyChart({ daily }: { daily: DailyCount[] }) {
  const [hovered, setHovered] = useState<number | null>(null);
  const [plotRef, width] = useElementWidth<HTMLDivElement>(600);
  const plotWidth = width - AXIS_GUTTER;
  const maxValue = niceMax(Math.max(1, ...daily.map((day) => day.checked)));
  const slot = plotWidth / daily.length;
  const barWidth = Math.max(2, slot - BAR_GAP);
  const scale = (value: number) => (value / maxValue) * CHART_HEIGHT;
  const gridValues = [0, maxValue / 2, maxValue];
  const hoveredDay = hovered === null ? null : daily[hovered];

  return (
    <figure className="history-chart">
      <div className="history-chart__legend" aria-hidden="true">
        <span className="legend-item">
          <span className="legend-swatch legend-swatch--clean" />
          Clean email
        </span>
        <span className="legend-item">
          <span className="legend-swatch legend-swatch--caught" />
          Threat caught
        </span>
      </div>
      <div className="history-chart__plot" ref={plotRef}>
        <svg
          viewBox={`0 0 ${width} ${CHART_HEIGHT + 24}`}
          role="img"
          aria-label={`Emails checked per day over the last ${daily.length} days, with threats caught highlighted. A table view follows.`}
          onMouseLeave={() => setHovered(null)}
        >
          {gridValues.map((value) => {
            const y = CHART_HEIGHT - scale(value);
            return (
              <g key={value}>
                <line className="chart-grid" x1={AXIS_GUTTER} x2={width} y1={y} y2={y} />
                <text className="chart-axis-label" x={AXIS_GUTTER - 6} y={y + 4} textAnchor="end">
                  {value}
                </text>
              </g>
            );
          })}
          {daily.map((day, index) => {
            const x = AXIS_GUTTER + index * slot + BAR_GAP / 2;
            const clean = day.checked - day.caught;
            const cleanHeight = scale(clean);
            const caughtHeight = scale(day.caught);
            const hasCaught = day.caught > 0;
            // 2px surface gap between the stacked segments.
            const caughtY = CHART_HEIGHT - cleanHeight - caughtHeight - (hasCaught ? 2 : 0);
            return (
              <g key={day.date} className={hovered === index ? "chart-bar is-hovered" : "chart-bar"}>
                {clean > 0 && (
                  <path
                    className="chart-bar__clean"
                    d={
                      hasCaught
                        ? `M${x},${CHART_HEIGHT} V${CHART_HEIGHT - cleanHeight} H${x + barWidth} V${CHART_HEIGHT} Z`
                        : topRoundedBar(x, CHART_HEIGHT - cleanHeight, barWidth, cleanHeight)
                    }
                  />
                )}
                {hasCaught && (
                  <path className="chart-bar__caught" d={topRoundedBar(x, caughtY, barWidth, caughtHeight)} />
                )}
                {/* Hit target: the full column, wider than the mark. */}
                <rect
                  className="chart-hit"
                  x={AXIS_GUTTER + index * slot}
                  y={0}
                  width={slot}
                  height={CHART_HEIGHT}
                  onMouseEnter={() => setHovered(index)}
                />
              </g>
            );
          })}
          <line className="chart-baseline" x1={AXIS_GUTTER} x2={width} y1={CHART_HEIGHT} y2={CHART_HEIGHT} />
          <text className="chart-axis-label" x={AXIS_GUTTER} y={CHART_HEIGHT + 18}>
            {formatDay(daily[0].date)}
          </text>
          <text className="chart-axis-label" x={width} y={CHART_HEIGHT + 18} textAnchor="end">
            Today
          </text>
        </svg>
        {hoveredDay && hovered !== null && (
          <div
            className={`chart-tooltip chart-tooltip--${tooltipAlign(hovered, daily.length)}`}
            role="status"
            style={{ left: `${AXIS_GUTTER + (hovered + 0.5) * slot}px` }}
          >
            <strong>{formatDay(hoveredDay.date, { weekday: "short", month: "short", day: "numeric" })}</strong>
            <span>{hoveredDay.checked} checked</span>
            <span className={hoveredDay.caught ? "chart-tooltip__caught" : undefined}>
              {hoveredDay.caught} {hoveredDay.caught === 1 ? "threat" : "threats"} caught
            </span>
          </div>
        )}
      </div>
      <details className="table-view">
        <summary>Show as a table</summary>
        <table>
          <thead>
            <tr>
              <th scope="col">Day</th>
              <th scope="col">Emails checked</th>
              <th scope="col">Threats caught</th>
            </tr>
          </thead>
          <tbody>
            {[...daily].reverse().map((day) => (
              <tr key={day.date}>
                <td>{formatDay(day.date, { weekday: "short", month: "short", day: "numeric" })}</td>
                <td>{day.checked}</td>
                <td>{day.caught}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </figure>
  );
}

function CategoryBreakdown({ history }: { history: History }) {
  if (history.categories.length === 0) {
    return <p className="empty-state__hint">Nothing caught in this period.</p>;
  }
  const max = Math.max(...history.categories.map((c) => c.count));
  return (
    <ul className="category-bars">
      {history.categories.map((item) => (
        <li key={item.category} className="category-bar">
          <span className="category-bar__label">{categoryLabel(item.category)}</span>
          <span className="category-bar__track">
            <span className="category-bar__fill" style={{ width: `${(item.count / max) * 100}%` }} />
          </span>
          <span className="category-bar__count">{item.count}</span>
        </li>
      ))}
    </ul>
  );
}

export function ProtectionHistory({
  history,
  loading,
  error,
}: {
  history: History | null;
  loading: boolean;
  error: string | null;
}) {
  if (loading) return <p className="loading-state">Loading history…</p>;
  if (error) return <p className="error">Failed to load history: {error}</p>;
  if (!history || history.emails_checked === 0) {
    return (
      <div className="empty-state">
        <p className="empty-state__title">No history yet</p>
        <p className="empty-state__hint">Once email is being checked, you&rsquo;ll see a day-by-day record here.</p>
      </div>
    );
  }

  const suspiciousShare = (history.threats_caught / history.emails_checked) * 100;
  return (
    <div className="history">
      <p className="history__summary">
        {history.first_scan_at && (
          <>
            Protecting this inbox since{" "}
            <strong>
              {new Date(history.first_scan_at).toLocaleDateString(undefined, {
                month: "long",
                day: "numeric",
                year: "numeric",
              })}
            </strong>
            .{" "}
          </>
        )}
        In the last {history.days} days, <strong>{history.threats_caught}</strong> of{" "}
        {history.emails_checked.toLocaleString()} emails ({suspiciousShare < 1 ? "<1" : suspiciousShare.toFixed(1)}%)
        were risky enough to flag.
      </p>

      <ImpactTiles history={history} />

      <section className="history__panel" aria-labelledby="daily-heading">
        <h3 id="daily-heading">Emails checked each day</h3>
        <DailyChart daily={history.daily} />
      </section>

      <section className="history__panel" aria-labelledby="caught-heading">
        <h3 id="caught-heading">What we caught</h3>
        <p className="history__panel-hint">
          Warning signs found in flagged messages. One message can show more than one.
        </p>
        <CategoryBreakdown history={history} />
      </section>
    </div>
  );
}
