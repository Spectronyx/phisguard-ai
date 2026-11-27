import type { Classification, RiskLevel, Severity } from "../types/api";

export function formatDate(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

export function formatPercent(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  return `${Math.round(value * 1000) / 10}%`;
}

export const classificationStyles: Record<
  Classification,
  { label: string; text: string; bg: string; border: string; dot: string }
> = {
  safe: {
    label: "Safe",
    text: "text-safe",
    bg: "bg-safe/10",
    border: "border-safe/30",
    dot: "bg-safe",
  },
  suspicious: {
    label: "Suspicious",
    text: "text-warn",
    bg: "bg-warn/10",
    border: "border-warn/30",
    dot: "bg-warn",
  },
  phishing: {
    label: "Phishing",
    text: "text-danger",
    bg: "bg-danger/10",
    border: "border-danger/30",
    dot: "bg-danger",
  },
};

export const riskLevelStyles: Record<RiskLevel, { label: string; text: string }> = {
  low: { label: "Low risk", text: "text-safe" },
  suspicious: { label: "Suspicious", text: "text-warn" },
  high: { label: "High risk", text: "text-danger" },
  critical: { label: "Critical", text: "text-danger" },
};

export const severityStyles: Record<Severity, { text: string; bg: string }> = {
  low: { text: "text-muted", bg: "bg-muted/10" },
  medium: { text: "text-warn", bg: "bg-warn/10" },
  high: { text: "text-danger", bg: "bg-danger/10" },
  critical: { text: "text-danger", bg: "bg-danger/15" },
};

export function riskColor(score: number): string {
  if (score >= 80) return "#fb7185";
  if (score >= 60) return "#f87171";
  if (score >= 30) return "#fbbf24";
  return "#34d399";
}

export function componentStatusLabel(status: string): string {
  switch (status) {
    case "ok":
      return "Active";
    case "degraded":
      return "Degraded";
    case "no_data":
      return "No data";
    case "unavailable":
      return "Unavailable";
    case "error":
      return "Error";
    case "skipped":
      return "Not applicable";
    default:
      return status;
  }
}

export function readNumber(
  details: Record<string, unknown>,
  key: string,
): number | null {
  const value = details[key];
  return typeof value === "number" ? value : null;
}

export function readString(
  details: Record<string, unknown>,
  key: string,
): string | null {
  const value = details[key];
  return typeof value === "string" ? value : null;
}
