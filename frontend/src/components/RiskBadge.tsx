import type { Classification } from "../types/api";
import { classificationStyles } from "../utils/format";

export default function RiskBadge({
  classification,
  size = "md",
}: {
  classification: Classification;
  size?: "sm" | "md";
}) {
  const style = classificationStyles[classification];
  return (
    <span
      className={`chip ${style.bg} ${style.border} ${style.text} ${
        size === "sm" ? "px-2 py-0.5 text-[10px]" : ""
      }`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${style.dot}`} />
      {style.label}
    </span>
  );
}
