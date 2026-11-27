import {
  Bot,
  CheckCircle2,
  Gauge,
  Link2,
  Lightbulb,
  LockKeyhole,
  Scale,
  ShieldAlert,
} from "lucide-react";
import type { AnalysisResult } from "../types/api";
import { formatDate, formatPercent, readNumber, readString } from "../utils/format";
import ComponentCard from "./ComponentCard";
import IndicatorList from "./IndicatorList";
import RiskBadge from "./RiskBadge";
import ScoreGauge from "./ScoreGauge";
import { SectionTitle } from "./Primitives";
import { Notice } from "./States";

function Facts({ result }: { result: AnalysisResult }) {
  const details = result.details;
  const facts: Array<{ label: string; value: string }> = [];

  const subject = readString(details, "subject");
  const senderDomain = readString(details, "sender_domain");
  const host = readString(details, "host");
  const domain = readString(details, "registrable_domain");
  const urlCount = readNumber(details, "url_count");
  const bodyChars = readNumber(details, "body_characters_analyzed");
  const rawLength = readNumber(details, "raw_length");

  if (subject) facts.push({ label: "Subject", value: subject });
  if (senderDomain) facts.push({ label: "Sender domain", value: senderDomain });
  if (host) facts.push({ label: "Host", value: host });
  if (domain) facts.push({ label: "Registrable domain", value: domain });
  if (urlCount !== null) facts.push({ label: "Embedded links", value: String(urlCount) });
  if (bodyChars !== null) facts.push({ label: "Body characters analysed", value: String(bodyChars) });
  if (rawLength !== null) facts.push({ label: "Input length", value: `${rawLength} chars` });
  facts.push({ label: "Scanned", value: formatDate(result.created_at) });

  return (
    <div className="flex flex-wrap gap-x-8 gap-y-3">
      {facts.map((fact) => (
        <div key={fact.label} className="min-w-[140px]">
          <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-muted">
            {fact.label}
          </p>
          <p className="mt-0.5 break-all text-sm text-ink">{fact.value}</p>
        </div>
      ))}
    </div>
  );
}

export default function ResultView({ result }: { result: AnalysisResult }) {
  const activeComponents = result.components.filter(
    (component) => component.status === "ok" && component.score !== null,
  );
  const skipped = result.components.filter((component) => component.status !== "ok");
  const notice = readString(result.details, "notice");

  return (
    <div className="space-y-6">
      <section className="panel overflow-hidden">
        <div className="grid gap-6 p-5 sm:p-6 lg:grid-cols-[180px_1fr]">
          <div className="flex justify-center lg:justify-start">
            <ScoreGauge
              score={result.risk_score}
              classification={result.classification}
              level={result.risk_level}
            />
          </div>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <RiskBadge classification={result.classification} />
              <span className="chip border-line bg-panel-2 text-muted">
                {result.scan_type === "email" ? "Email scan" : "URL scan"} #{result.scan_id}
              </span>
              {result.llm_used && (
                <span className="chip border-violet/30 bg-violet/10 text-violet">
                  <Bot size={11} /> {result.llm_sent_to_provider ? "External LLM used" : "Local LLM used"}
                </span>
              )}
            </div>
            <h2 className="mt-3 break-words text-lg font-semibold leading-snug text-ink">
              {result.input_summary || "Analysis result"}
            </h2>
            <p className="mt-2 text-sm leading-relaxed text-muted">{result.explanation}</p>

            <div className="mt-4 grid gap-3 sm:grid-cols-2">
              <div className="rounded-xl border border-line bg-panel-2/50 p-3">
                <p className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.14em] text-muted">
                  <Gauge size={12} /> Model confidence
                </p>
                <p className="mt-1 font-mono text-xl font-bold text-ink">
                  {result.model_confidence === null
                    ? "—"
                    : formatPercent(result.model_confidence)}
                </p>
                <p className="mt-0.5 text-[10px] text-muted">
                  Per-model certainty, not the risk score
                </p>
              </div>
              <div className="rounded-xl border border-line bg-panel-2/50 p-3">
                <p className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.14em] text-muted">
                  <Scale size={12} /> Evidence modules
                </p>
                <p className="mt-1 font-mono text-xl font-bold text-ink">
                  {activeComponents.length}
                  <span className="text-xs text-muted">/{result.components.length} active</span>
                </p>
                <p className="mt-0.5 text-[10px] text-muted">
                  Missing modules are excluded, not scored as zero
                </p>
              </div>
            </div>

            <div className="mt-4 rounded-xl border border-accent/25 bg-accent/5 p-3.5">
              <p className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.14em] text-accent">
                <Lightbulb size={12} /> Recommended action
              </p>
              <p className="mt-1 text-sm leading-relaxed text-ink">{result.recommendation}</p>
            </div>

            {result.llm_sent_to_provider && (
              <div className="mt-3">
                <Notice tone="warn">
                  LLM semantic analysis is enabled in this deployment: email content was sent to the
                  configured external provider. All other analysis is local.
                </Notice>
              </div>
            )}
          </div>
        </div>

        <div className="border-t border-line bg-panel-2/30 px-5 py-4 sm:px-6">
          <Facts result={result} />
        </div>
      </section>

      <section>
        <SectionTitle
          title="How the risk score was built"
          hint="Weighted mean of available modules + capped corroboration bonus"
        />
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {result.components.map((component) => (
            <ComponentCard key={component.name} component={component} />
          ))}
        </div>
        {skipped.length > 0 && (
          <p className="mt-3 text-xs text-muted">
            {skipped.length} module(s) did not contribute:{" "}
            {skipped.map((component) => `${component.label} (${component.status})`).join(", ")}.
          </p>
        )}
      </section>

      <section className="grid gap-6 lg:grid-cols-2">
        <div>
          <SectionTitle title={`Warning indicators (${result.indicators.length})`} />
          <IndicatorList indicators={result.indicators} />
        </div>

        <div className="space-y-6">
          {result.url_results.length > 0 && (
            <div>
              <SectionTitle
                title={`Embedded URLs (${result.url_results.length})`}
                hint="Parsed as text only"
              />
              <div className="overflow-hidden rounded-xl border border-line">
                {result.url_results.map((item) => (
                  <div
                    key={`${item.url}-${item.risk_score}`}
                    className="flex items-center justify-between gap-3 border-b border-line bg-panel/60 px-4 py-3 last:border-0"
                  >
                    <div className="min-w-0">
                      <p className="flex items-center gap-1.5 truncate font-mono text-xs text-ink">
                        <Link2 size={12} className="shrink-0 text-muted" />
                        <span className="truncate">{item.url}</span>
                      </p>
                      <p className="mt-0.5 text-[11px] text-muted">
                        {item.domain || "unknown domain"}
                        {item.error ? ` · ${item.error}` : ""}
                      </p>
                    </div>
                    <div className="flex shrink-0 items-center gap-2">
                      <span className="font-mono text-sm font-bold text-ink">
                        {Math.round(item.risk_score)}
                      </span>
                      <RiskBadge classification={item.classification} size="sm" />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div>
            <SectionTitle title="Privacy & safety" />
            <div className="space-y-2">
              <div className="flex items-start gap-2.5 rounded-xl border border-line bg-panel-2/40 p-3 text-xs text-muted">
                <LockKeyhole size={14} className="mt-0.5 shrink-0 text-safe" />
                <span>
                  Submitted URLs are parsed as strings and never fetched, resolved, or executed.
                </span>
              </div>
              <div className="flex items-start gap-2.5 rounded-xl border border-line bg-panel-2/40 p-3 text-xs text-muted">
                <CheckCircle2 size={14} className="mt-0.5 shrink-0 text-safe" />
                <span>
                  {notice ??
                    "Only a short summary and derived features are stored; the full email body is not persisted by default."}
                </span>
              </div>
              <div className="flex items-start gap-2.5 rounded-xl border border-line bg-panel-2/40 p-3 text-xs text-muted">
                <ShieldAlert size={14} className="mt-0.5 shrink-0 text-warn" />
                <span>
                  A low score is not a guarantee of safety. Absence of graph or model data is not
                  evidence of legitimacy.
                </span>
              </div>
            </div>
          </div>
        </div>
      </section>

      <details className="panel group p-4">
        <summary className="cursor-pointer list-none text-sm font-semibold text-ink">
          Technical details
          <span className="ml-2 text-xs font-normal text-muted">
            raw component and feature payload
          </span>
        </summary>
        <pre className="mt-3 max-h-96 overflow-auto rounded-xl border border-line bg-canvas/70 p-3 font-mono text-[11px] leading-relaxed text-muted">
          {JSON.stringify(result.details, null, 2)}
        </pre>
      </details>
    </div>
  );
}
