import type { Classification } from "../types/api";
import { classificationStyles, riskColor } from "../utils/format";

export default function ScoreGauge({
  score,
  classification,
  level,
}: {
  score: number;
  classification: Classification;
  level: string;
}) {
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const clamped = Math.max(0, Math.min(100, score));
  const offset = circumference - (clamped / 100) * circumference;
  const color = riskColor(clamped);
  const style = classificationStyles[classification];

  return (
    <div className="relative grid h-40 w-40 place-items-center">
      <svg viewBox="0 0 140 140" className="h-40 w-40 -rotate-90">
        <circle
          cx="70"
          cy="70"
          r={radius}
          fill="none"
          stroke="#1e2a3d"
          strokeWidth="11"
        />
        <circle
          cx="70"
          cy="70"
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth="11"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: "stroke-dashoffset 700ms ease, stroke 300ms ease" }}
        />
      </svg>
      <div className="absolute inset-0 grid place-content-center text-center">
        <p className="font-mono text-4xl font-bold leading-none" style={{ color }}>
          {clamped}
        </p>
        <p className="mt-1 text-[10px] font-semibold uppercase tracking-[0.18em] text-muted">
          risk / 100
        </p>
        <p className={`mt-2 text-xs font-bold uppercase tracking-[0.14em] ${style.text}`}>
          {level === "critical" ? "Critical" : style.label}
        </p>
      </div>
    </div>
  );
}
