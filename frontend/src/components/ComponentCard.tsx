import { CheckCircle2, CircleSlash, MinusCircle, TriangleAlert } from "lucide-react";
import type { AnalysisComponent } from "../types/api";
import { componentStatusLabel, formatPercent } from "../utils/format";

const statusIcon = {
  ok: CheckCircle2,
  degraded: TriangleAlert,
  no_data: CircleSlash,
  unavailable: CircleSlash,
  error: TriangleAlert,
  skipped: MinusCircle,
};

const statusColor = {
  ok: "text-safe",
  degraded: "text-warn",
  no_data: "text-muted",
  unavailable: "text-muted",
  error: "text-danger",
  skipped: "text-muted",
};

export default function ComponentCard({ component }: { component: AnalysisComponent }) {
  const Icon = statusIcon[component.status];
  const available = component.status === "ok" && component.score !== null;
  const score = component.score ?? 0;

  return (
    <div className="panel p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="truncate text-sm font-semibold text-ink">{component.label}</p>
          <p className="mt-0.5 font-mono text-[10px] uppercase tracking-wider text-muted">
            {component.name}
          </p>
        </div>
        <span className={`flex shrink-0 items-center gap-1 text-[11px] font-semibold ${statusColor[component.status]}`}>
          <Icon size={13} />
          {componentStatusLabel(component.status)}
        </span>
      </div>

      <div className="mt-4 flex items-end justify-between gap-3">
        <div>
          <p className="font-mono text-2xl font-bold leading-none text-ink">
            {available ? Math.round(score) : "—"}
            {available && <span className="ml-0.5 text-xs font-medium text-muted">/100</span>}
          </p>
          <p className="mt-1 text-[11px] text-muted">
            {component.confidence !== null
              ? `Model confidence ${formatPercent(component.confidence)}`
              : "Deterministic score"}
          </p>
        </div>
        {component.weight !== null && (
          <div className="text-right text-[11px] text-muted">
            <p>weight {formatPercent(component.weight)}</p>
            <p>contribution {component.contribution ?? "—"}</p>
          </div>
        )}
      </div>

      <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-line">
        <div
          className={`h-full rounded-full ${
            score >= 80 ? "bg-danger" : score >= 60 ? "bg-danger/80" : score >= 30 ? "bg-warn" : "bg-safe"
          }`}
          style={{ width: `${available ? Math.min(100, score) : 0}%` }}
        />
      </div>

      <p className="mt-3 text-xs leading-relaxed text-muted">{component.explanation}</p>
    </div>
  );
}
