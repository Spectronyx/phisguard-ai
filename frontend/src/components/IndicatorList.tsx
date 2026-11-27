import { ShieldAlert } from "lucide-react";
import type { Indicator } from "../types/api";
import { severityStyles } from "../utils/format";

export default function IndicatorList({
  indicators,
  emptyLabel = "No warning indicators were triggered.",
}: {
  indicators: Indicator[];
  emptyLabel?: string;
}) {
  if (indicators.length === 0) {
    return (
      <div className="rounded-xl border border-line bg-panel-2/40 px-4 py-5 text-sm text-muted">
        {emptyLabel}
      </div>
    );
  }

  return (
    <ul className="divide-y divide-line overflow-hidden rounded-xl border border-line">
      {indicators.map((indicator, index) => {
        const style = severityStyles[indicator.severity];
        return (
          <li
            key={`${indicator.name}-${index}`}
            className="flex items-start gap-3 bg-panel/60 px-4 py-3"
          >
            <ShieldAlert size={15} className={`mt-0.5 shrink-0 ${style.text}`} />
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <p className="text-sm font-semibold text-ink">{indicator.name}</p>
                <span className={`rounded px-1.5 py-0.5 text-[10px] font-bold uppercase ${style.bg} ${style.text}`}>
                  {indicator.severity}
                </span>
                <span className="font-mono text-[10px] uppercase tracking-wider text-muted/70">
                  {indicator.source}
                </span>
              </div>
              <p className="mt-1 text-xs leading-relaxed text-muted">{indicator.description}</p>
            </div>
          </li>
        );
      })}
    </ul>
  );
}
