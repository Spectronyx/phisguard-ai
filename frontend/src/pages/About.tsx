import { useEffect, useState } from "react";
import {
  BookOpen,
  BrainCircuit,
  Database,
  GitBranch,
  LockKeyhole,
  Network,
  ShieldCheck,
  SlidersHorizontal,
  TriangleAlert,
} from "lucide-react";
import { api, ApiError } from "../services/api";
import type { HealthStatus, ModelStatus } from "../types/api";
import { PageHeader, SectionTitle } from "../components/Primitives";
import { ErrorState, Loading, Notice } from "../components/States";

const weights = [
  { name: "Email ML model", value: "0.30" },
  { name: "URL ML model", value: "0.30" },
  { name: "Email rules", value: "0.15" },
  { name: "URL rules", value: "0.10" },
  { name: "Domain graph", value: "0.05" },
  { name: "Local LLM", value: "0.10" },
];

function metric(value: unknown, path: string[]): string | null {
  let cursor: unknown = value;
  for (const key of path) {
    if (typeof cursor !== "object" || cursor === null) return null;
    cursor = (cursor as Record<string, unknown>)[key];
  }
  return typeof cursor === "number" ? String(cursor) : null;
}

function ModelCard({
  name,
  algorithm,
  available,
  metrics,
}: {
  name: string;
  algorithm: string | null;
  available: boolean;
  metrics: Record<string, unknown>;
}) {
  const f1 = metric(metrics, ["test", "f1"]);
  const precision = metric(metrics, ["test", "precision"]);
  const recall = metric(metrics, ["test", "recall"]);
  const auc = metric(metrics, ["test", "roc_auc"]);
  return (
    <div className="panel p-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-sm font-semibold text-ink">{name}</p>
          <p className="mt-0.5 font-mono text-[11px] text-muted">{algorithm ?? "unknown"}</p>
        </div>
        <span
          className={`chip ${
            available
              ? "border-safe/30 bg-safe/10 text-safe"
              : "border-warn/30 bg-warn/10 text-warn"
          }`}
        >
          {available ? "Loaded" : "Missing"}
        </span>
      </div>
      {f1 ? (
        <dl className="mt-3 grid grid-cols-2 gap-2 text-xs">
          {[
            ["F1", f1],
            ["Precision", precision],
            ["Recall", recall],
            ["ROC-AUC", auc],
          ].map(([label, value]) => (
            <div key={String(label)} className="rounded-lg bg-panel-2/60 px-2.5 py-2">
              <dt className="text-[10px] uppercase tracking-[0.12em] text-muted">{label}</dt>
              <dd className="mt-0.5 font-mono text-sm font-semibold text-ink">{value ?? "—"}</dd>
            </div>
          ))}
        </dl>
      ) : (
        <p className="mt-3 text-xs text-muted">
          No test metrics were stored for this artifact. Missing artifacts fall back to
          deterministic analysis.
        </p>
      )}
    </div>
  );
}

export default function About() {
  const [status, setStatus] = useState<ModelStatus | null>(null);
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    Promise.all([api.modelStatus(), api.health()])
      .then(([modelStatus, healthStatus]) => {
        if (!active) return;
        setStatus(modelStatus);
        setHealth(healthStatus);
      })
      .catch((err: unknown) => {
        if (active) setError(err instanceof ApiError ? err.message : "Failed to load system status.");
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  if (loading) return <Loading label="Loading system status…" />;
  if (error) return <ErrorState message={error} />;
  if (!status) return null;

  return (
    <div>
      <PageHeader
        eyebrow="System documentation"
        title="About & Limits"
        description="What PhishGuard AI actually does, which data and models it uses, and where its analysis stops. These limits are part of the design, not fine print."
        actions={
          <span className="chip border-line bg-panel-2 text-muted">
            <ShieldCheck size={12} /> v{health?.version ?? "1.0.0"}
          </span>
        }
      />

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <ModelCard
          name="Email NLP classifier"
          algorithm={status.email_model.algorithm}
          available={status.email_model.available}
          metrics={status.email_model.metrics}
        />
        <ModelCard
          name="URL ML classifier"
          algorithm={status.url_model.algorithm}
          available={status.url_model.available}
          metrics={status.url_model.metrics}
        />
        <ModelCard
          name="Local LLM (DistilBERT)"
          algorithm={status.local_llm?.algorithm ?? "not trained"}
          available={Boolean(status.local_llm?.available)}
          metrics={status.local_llm?.metrics ?? {}}
        />
        <div className="panel p-4">
          <div className="flex items-start justify-between gap-3">
            <div>
              <p className="text-sm font-semibold text-ink">Domain graph</p>
              <p className="mt-0.5 font-mono text-[11px] text-muted">NetworkX analytics</p>
            </div>
            <span
              className={`chip ${
                status.domain_graph.available
                  ? "border-safe/30 bg-safe/10 text-safe"
                  : "border-warn/30 bg-warn/10 text-warn"
              }`}
            >
              {status.domain_graph.available ? "Loaded" : "Missing"}
            </span>
          </div>
          <p className="mt-3 text-xs leading-relaxed text-muted">
            Hostname and registrable-domain relationships, malicious-corpus labels and
            brand-lookalike edges. This is graph analytics — not a Graph Neural Network — and it
            uses a static snapshot, not WHOIS, DNS or live reputation lookups.
          </p>
          <p className="mt-3 font-mono text-[11px] text-muted">
            inference mode: <span className="text-ink">{status.inference_mode}</span>
          </p>
        </div>
      </div>

      {status.notes.length > 0 && (
        <div className="mt-4">
          <Notice tone="warn">{status.notes.join(" ")}</Notice>
        </div>
      )}

      <div className="mt-6 grid gap-4 lg:grid-cols-2">
        <section className="panel p-5">
          <SectionTitle title="Analysis pipeline" hint="each stage degrades independently" />
          <ol className="space-y-3">
            {[
              ["Input normalisation", "Email text is truncated and URLs are extracted as strings. Embedded links are never fetched."],
              ["Email model", "TF-IDF word 1–2 grams + Logistic Regression trained on the Nazario phishing corpus and SpamAssassin ham."],
              ["URL model", "Hostname character 3–5 grams + host-centric numeric features + a Cisco Umbrella popularity prior, trained on real benign and malicious URL corpora."],
              ["Deterministic rules", "Transparent lexical checks for brand impersonation, IP hosts, punycode, shorteners, credential keywords and more."],
              ["Domain graph", "NetworkX lookup of corpus labels, malicious neighbours and brand-lookalike relationships."],
              ["Local LLM", "A DistilBERT classifier fine-tuned on the real email corpus runs locally on this machine. It is private (sent_to_provider=false); an external API is only an opt-in fallback."],
              ["Risk aggregation", "Weighted mean over available modules, plus a small capped bonus when several modules agree."],
            ].map(([title, description], index) => (
              <li key={title} className="flex gap-3">
                <span className="mt-0.5 grid h-6 w-6 shrink-0 place-items-center rounded-md bg-accent/10 font-mono text-[11px] font-bold text-accent">
                  {index + 1}
                </span>
                <div>
                  <p className="text-sm font-semibold text-ink">{title}</p>
                  <p className="mt-0.5 text-xs leading-relaxed text-muted">{description}</p>
                </div>
              </li>
            ))}
          </ol>
        </section>

        <div className="space-y-4">
          <section className="panel p-5">
            <SectionTitle title="Risk weights" hint="renormalised over available modules" />
            <div className="grid grid-cols-2 gap-2">
              {weights.map((item) => (
                <div key={item.name} className="flex items-center justify-between rounded-lg bg-panel-2/60 px-3 py-2">
                  <span className="text-xs text-muted">{item.name}</span>
                  <span className="font-mono text-xs font-semibold text-ink">{item.value}</span>
                </div>
              ))}
            </div>
            <p className="mt-3 text-[11px] leading-relaxed text-muted">
              A missing module is excluded from the weighted mean rather than scored as zero. The
              0–100 risk score is separate from per-model confidence.
            </p>
          </section>

          <section className="panel p-5">
            <SectionTitle title="Data sources" />
            <ul className="space-y-2 text-xs leading-relaxed text-muted">
              <li className="flex gap-2"><Database size={13} className="mt-0.5 shrink-0 text-accent" /> Nazario phishing corpus 2019–2025 (CC-BY-4.0) and SpamAssassin ham for the email model.</li>
              <li className="flex gap-2"><Database size={13} className="mt-0.5 shrink-0 text-accent" /> Kaggle Malicious URLs Dataset (CC0, derived from ISCX-URL-2016) and Phishing.Database (CC0) for the URL model.</li>
              <li className="flex gap-2"><Database size={13} className="mt-0.5 shrink-0 text-accent" /> Cisco Umbrella top-1M public ranking as a popularity prior, not a safety guarantee.</li>
            </ul>
          </section>
        </div>
      </div>

      <div className="mt-4 grid gap-4 md:grid-cols-2">
        <section className="panel border-warn/20 p-5">
          <SectionTitle title="Honest limitations" />
          <ul className="space-y-2.5 text-xs leading-relaxed text-muted">
            <li className="flex gap-2"><TriangleAlert size={13} className="mt-0.5 shrink-0 text-warn" /> Email metrics are measured on a corpus whose legitimate messages are from 2003 while phishing messages span 2019–2025; this temporal mismatch can inflate measured performance.</li>
            <li className="flex gap-2"><TriangleAlert size={13} className="mt-0.5 shrink-0 text-warn" /> URL detection is substantially harder: the held-out test F1 is well below the email model and there are false positives on unseen legitimate hosts. Treat the score as supporting evidence.</li>
            <li className="flex gap-2"><TriangleAlert size={13} className="mt-0.5 shrink-0 text-warn" /> The domain graph is a static corpus snapshot. No WHOIS, DNS, IP reputation, sandbox detonation or live blocklist lookup is performed.</li>
            <li className="flex gap-2"><TriangleAlert size={13} className="mt-0.5 shrink-0 text-warn" /> Heuristic and ML signals can be evaded by novel campaigns. A low risk score is not proof of safety.</li>
          </ul>
        </section>

        <section className="panel border-safe/20 p-5">
          <SectionTitle title="Privacy & safety by design" />
          <ul className="space-y-2.5 text-xs leading-relaxed text-muted">
            <li className="flex gap-2"><LockKeyhole size={13} className="mt-0.5 shrink-0 text-safe" /> Submitted URLs and attachments are never fetched, opened or executed.</li>
            <li className="flex gap-2"><LockKeyhole size={13} className="mt-0.5 shrink-0 text-safe" /> Full email bodies are not stored; only a short summary, hash and derived indicators are persisted.</li>
            <li className="flex gap-2"><LockKeyhole size={13} className="mt-0.5 shrink-0 text-safe" /> No API keys are stored in source. Configuration comes from environment variables.</li>
            <li className="flex gap-2"><LockKeyhole size={13} className="mt-0.5 shrink-0 text-safe" /> {status.local_llm_available ? "The local DistilBERT semantic model runs on this machine; email content is never sent to an external provider." : status.llm_configured ? "The external LLM fallback is enabled; email content may be sent to the configured provider when the local model is unavailable (disclosed per scan)." : "LLM analysis is disabled; no email content leaves the machine."}</li>
          </ul>
        </section>
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-x-5 gap-y-2 text-[11px] text-muted">
        <span className="flex items-center gap-1.5"><BrainCircuit size={13} /> SIH25159 · AICTE</span>
        <span className="flex items-center gap-1.5"><GitBranch size={13} /> CSE473 academic project</span>
        <span className="flex items-center gap-1.5"><Network size={13} /> FastAPI + React + scikit-learn</span>
        <span className="flex items-center gap-1.5"><SlidersHorizontal size={13} /> {health?.artifacts_ready ? "Artifacts ready" : "Degraded (rules fallback)"}</span>
        <span className="flex items-center gap-1.5"><BookOpen size={13} /> Metrics come from actual runs</span>
      </div>
    </div>
  );
}
