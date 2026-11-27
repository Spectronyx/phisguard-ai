import { FormEvent, useState } from "react";
import { Link } from "react-router-dom";
import { Link2, Mail, RotateCcw, ScanSearch, Send } from "lucide-react";
import { api, ApiError } from "../services/api";
import type { AnalysisResult, ValidationIssue } from "../types/api";
import { PageHeader } from "../components/Primitives";
import { ErrorState, Loading, Notice } from "../components/States";
import ResultView from "../components/ResultView";

const examples = [
  {
    label: "Phishing URL",
    value:
      "https://adobe-reader-283901.standard.us-east-1.oortech.com/documents.org?778780533c3344e3709mnv708b00a077878053",
  },
  {
    label: "Brand lookalike",
    value: "http://paypal-secure-login.xyz/verify-account",
  },
  { label: "Google", value: "https://www.google.com/" },
  { label: "GitHub link", value: "https://github.com/microsoft/vscode" },
];

export default function UrlScanner() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [issues, setIssues] = useState<ValidationIssue[]>([]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setLoading(true);
    setError(null);
    setIssues([]);
    try {
      const analysis = await api.analyzeUrl({ url: url.trim() });
      setResult(analysis);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
        setIssues(err.issues);
      } else {
        setError("The URL could not be analysed.");
      }
    } finally {
      setLoading(false);
    }
  }

  function reset() {
    setUrl("");
    setResult(null);
    setError(null);
    setIssues([]);
  }

  return (
    <div>
      <PageHeader
        eyebrow="URL analysis"
        title="URL Scanner"
        description="Lexical URL features, hostname character n-grams, deterministic threat rules and domain-graph context. The URL is parsed as text only and is never fetched."
        actions={
          <Link to="/email" className="btn-ghost">
            <Mail size={15} /> Scan an email instead
          </Link>
        }
      />

      <form onSubmit={submit} className="panel mb-6 p-5">
        <div className="mb-4 flex flex-wrap gap-2">
          {examples.map((example) => (
            <button
              key={example.label}
              type="button"
              onClick={() => {
                setUrl(example.value);
                setResult(null);
                setError(null);
              }}
              className="chip border-line bg-panel-2 text-muted transition hover:border-accent/40 hover:text-accent"
            >
              {example.label}
            </button>
          ))}
        </div>

        <label className="label" htmlFor="url">
          URL or hostname
        </label>
        <div className="flex flex-col gap-2 sm:flex-row">
          <div className="relative flex-1">
            <Link2 size={16} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
            <input
              id="url"
              className="input pl-9 font-mono text-[13px]"
              value={url}
              onChange={(event) => setUrl(event.target.value)}
              placeholder="https://example.com/login"
              maxLength={2048}
              autoComplete="off"
              spellCheck={false}
            />
          </div>
          <button type="submit" className="btn-primary sm:w-44" disabled={loading || url.trim().length < 3}>
            {loading ? (
              <>
                <ScanSearch size={16} className="animate-pulse-soft" /> Analysing…
              </>
            ) : (
              <>
                <Send size={16} /> Analyse URL
              </>
            )}
          </button>
          <button type="button" className="btn-ghost" onClick={reset} title="Clear">
            <RotateCcw size={16} />
          </button>
        </div>

        <div className="mt-3">
          <Notice tone="warn">
            Do not submit live malicious links expecting them to be opened. PhishGuard never
            connects to the URL; analysis is purely lexical and uses the local model, rules and
            domain graph.
          </Notice>
        </div>
      </form>

      {loading && <Loading label="Extracting features and scoring the URL…" />}
      {!loading && error && <ErrorState message={error} issues={issues} onRetry={() => setError(null)} />}
      {!loading && !error && !result && (
        <div className="grid min-h-[320px] place-items-center rounded-2xl border border-dashed border-line px-6 text-center">
          <div>
            <div className="mx-auto grid h-12 w-12 place-items-center rounded-2xl bg-accent/10 text-accent ring-1 ring-accent/20">
              <Link2 size={22} />
            </div>
            <p className="mt-4 text-sm font-semibold text-ink">No URL analysed yet</p>
            <p className="mx-auto mt-1 max-w-md text-sm text-muted">
              Paste a URL or pick an example. Results include the raw model probability, the
              calibrated score and every triggered rule.
            </p>
          </div>
        </div>
      )}
      {!loading && !error && result && <ResultView result={result} />}
    </div>
  );
}
