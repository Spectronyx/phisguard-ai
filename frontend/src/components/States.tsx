import { AlertTriangle, Loader2, SearchX } from "lucide-react";
import type { ReactNode } from "react";
import type { ValidationIssue } from "../types/api";

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-3 py-16 text-sm text-muted">
      <Loader2 size={18} className="animate-spin text-accent" />
      {label}
    </div>
  );
}

export function ErrorState({
  message,
  issues = [],
  onRetry,
}: {
  message: string;
  issues?: ValidationIssue[];
  onRetry?: () => void;
}) {
  return (
    <div className="panel border-danger/30 p-5">
      <div className="flex items-start gap-3">
        <div className="mt-0.5 grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-danger/10 text-danger">
          <AlertTriangle size={17} />
        </div>
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-danger">Something went wrong</p>
          <p className="mt-1 text-sm text-muted">{message}</p>
          {issues.length > 0 && (
            <ul className="mt-2 space-y-1 text-xs text-muted">
              {issues.map((issue) => (
                <li key={`${issue.field}-${issue.message}`}>
                  <span className="font-mono text-danger">{issue.field || "input"}</span>:{" "}
                  {issue.message}
                </li>
              ))}
            </ul>
          )}
          {onRetry && (
            <button type="button" className="btn-ghost mt-3" onClick={onRetry}>
              Try again
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

export function EmptyState({
  title,
  description,
  action,
}: {
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="grid place-items-center rounded-2xl border border-dashed border-line px-6 py-14 text-center">
      <SearchX size={26} className="text-muted/60" />
      <p className="mt-3 text-sm font-semibold text-ink">{title}</p>
      <p className="mt-1 max-w-md text-sm text-muted">{description}</p>
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function Notice({
  children,
  tone = "info",
}: {
  children: ReactNode;
  tone?: "info" | "warn";
}) {
  return (
    <div
      className={`rounded-xl border px-3.5 py-2.5 text-xs leading-relaxed ${
        tone === "warn"
          ? "border-warn/30 bg-warn/5 text-warn"
          : "border-line bg-panel-2/50 text-muted"
      }`}
    >
      {children}
    </div>
  );
}
