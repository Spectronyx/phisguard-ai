import { FormEvent, useState } from "react";
import { Link } from "react-router-dom";
import { Link2, Mail, RotateCcw, ScanSearch, Send } from "lucide-react";
import { api, ApiError } from "../services/api";
import type { AnalysisResult, ValidationIssue } from "../types/api";
import { PageHeader } from "../components/Primitives";
import { ErrorState, Loading, Notice } from "../components/States";
import ResultView from "../components/ResultView";

const examples = {
  phishing: {
    label: "Phishing example",
    subject: "URGENT: Your SBI account will be suspended",
    sender: "SBI Support <alerts@sbi-verify.xyz>",
    body:
      "Dear Customer,\n\nWe detected unauthorized access to your account. You must verify your account within 24 hours or it will be permanently suspended. Enter your password and OTP at http://sbi-secure-login.xyz/verify to restore access.\n\nFailure to comply will result in legal action.",
  },
  legitimate: {
    label: "Legitimate example",
    subject: "CS473 project review schedule",
    sender: "sharma@university.edu",
    body:
      "Hi Rajneesh,\n\nThe project review is on Friday at 3 PM in Lab 4. Please bring the current report and demo. Let me know if the time does not work.\n\nRegards,\nDr. Sharma",
  },
  invoice: {
    label: "Invoice lure",
    subject: "Invoice INV-88421 payment overdue",
    sender: "billing@docusign-billing.top",
    body:
      "Dear customer,\n\nPlease find the attached invoice. A payment of USD 4,850 is required immediately by bank transfer. Open the attached invoice.html to view the beneficiary details. This is confidential; do not tell anyone.\n\nContact support@docusign-billing.top.",
  },
};

type ExampleKey = keyof typeof examples;

export default function EmailScanner() {
  const [subject, setSubject] = useState("");
  const [sender, setSender] = useState("");
  const [body, setBody] = useState("");
  const [urls, setUrls] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [issues, setIssues] = useState<ValidationIssue[]>([]);

  function applyExample(key: ExampleKey) {
    setSubject(examples[key].subject);
    setSender(examples[key].sender);
    setBody(examples[key].body);
    setUrls("");
    setResult(null);
    setError(null);
    setIssues([]);
  }

  function reset() {
    setSubject("");
    setSender("");
    setBody("");
    setUrls("");
    setResult(null);
    setError(null);
    setIssues([]);
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    setLoading(true);
    setError(null);
    setIssues([]);
    try {
      const payload = {
        subject,
        body,
        sender: sender.trim() ? sender.trim() : null,
        urls: urls
          .split(/[\n,]+/)
          .map((value) => value.trim())
          .filter(Boolean),
      };
      const analysis = await api.analyzeEmail(payload);
      setResult(analysis);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
        setIssues(err.issues);
      } else {
        setError("The email could not be analysed.");
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <div>
      <PageHeader
        eyebrow="Email analysis"
        title="Email Scanner"
        description="Paste an email to score it with the TF-IDF email model, social-engineering rules, embedded-URL analysis and domain-graph evidence. The body is analysed in memory and is not stored."
        actions={
          <Link to="/url" className="btn-ghost">
            <Link2 size={15} /> Scan a URL instead
          </Link>
        }
      />

      <div className="grid gap-6 xl:grid-cols-[minmax(0,420px)_1fr]">
        <form onSubmit={submit} className="panel h-fit p-5">
          <div className="mb-4 flex flex-wrap gap-2">
            {(Object.keys(examples) as ExampleKey[]).map((key) => (
              <button
                key={key}
                type="button"
                onClick={() => applyExample(key)}
                className="chip border-line bg-panel-2 text-muted transition hover:border-accent/40 hover:text-accent"
              >
                {examples[key].label}
              </button>
            ))}
          </div>

          <label className="label" htmlFor="subject">
            Subject
          </label>
          <input
            id="subject"
            className="input"
            value={subject}
            onChange={(event) => setSubject(event.target.value)}
            placeholder="e.g. URGENT: Your account will be suspended"
            maxLength={500}
          />

          <div className="mt-4">
            <label className="label" htmlFor="sender">
              Sender <span className="font-normal normal-case tracking-normal text-muted/70">(optional)</span>
            </label>
            <input
              id="sender"
              className="input"
              value={sender}
              onChange={(event) => setSender(event.target.value)}
              placeholder="alerts@example.com"
              maxLength={320}
            />
          </div>

          <div className="mt-4">
            <label className="label" htmlFor="body">
              Body
            </label>
            <textarea
              id="body"
              className="input min-h-[220px] resize-y font-mono text-[12.5px] leading-relaxed"
              value={body}
              onChange={(event) => setBody(event.target.value)}
              placeholder="Paste the email body here…"
              maxLength={50000}
            />
            <p className="mt-1 text-right font-mono text-[10px] text-muted/70">
              {body.length.toLocaleString()} / 50,000
            </p>
          </div>

          <div className="mt-3">
            <label className="label" htmlFor="urls">
              Extra URLs <span className="font-normal normal-case tracking-normal text-muted/70">(optional, one per line)</span>
            </label>
            <textarea
              id="urls"
              className="input min-h-[70px] resize-y font-mono text-[12px]"
              value={urls}
              onChange={(event) => setUrls(event.target.value)}
              placeholder="https://example.com/login"
            />
            <p className="mt-1 text-[10px] text-muted/70">
              URLs are parsed as text. They are never requested or opened.
            </p>
          </div>

          <div className="mt-5 flex gap-2">
            <button type="submit" className="btn-primary flex-1" disabled={loading || (!subject.trim() && !body.trim())}>
              {loading ? (
                <>
                  <ScanSearch size={16} className="animate-pulse-soft" /> Analysing…
                </>
              ) : (
                <>
                  <Send size={16} /> Analyse email
                </>
              )}
            </button>
            <button type="button" className="btn-ghost" onClick={reset} title="Clear form">
              <RotateCcw size={16} />
            </button>
          </div>

          <div className="mt-4">
            <Notice>
              <Mail size={12} className="mr-1 inline" />
              Only a short summary and derived indicators are persisted. Full email bodies are not
              stored by default.
            </Notice>
          </div>
        </form>

        <div className="min-w-0">
          {loading && <Loading label="Running local models, rules and graph analytics…" />}
          {!loading && error && (
            <ErrorState message={error} issues={issues} onRetry={() => setError(null)} />
          )}
          {!loading && !error && !result && (
            <div className="grid h-full min-h-[420px] place-items-center rounded-2xl border border-dashed border-line px-6 text-center">
              <div>
                <div className="mx-auto grid h-12 w-12 place-items-center rounded-2xl bg-accent/10 text-accent ring-1 ring-accent/20">
                  <Mail size={22} />
                </div>
                <p className="mt-4 text-sm font-semibold text-ink">No analysis yet</p>
                <p className="mx-auto mt-1 max-w-sm text-sm text-muted">
                  Submit an email or load an example to see the risk score, module breakdown and
                  evidence.
                </p>
              </div>
            </div>
          )}
          {!loading && !error && result && <ResultView result={result} />}
        </div>
      </div>
    </div>
  );
}
