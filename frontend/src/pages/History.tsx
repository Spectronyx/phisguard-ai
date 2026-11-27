import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ChevronLeft, ChevronRight, Filter, History as HistoryIcon, Search } from "lucide-react";
import { api, ApiError } from "../services/api";
import type { ScanPage } from "../types/api";
import { PageHeader } from "../components/Primitives";
import { EmptyState, ErrorState, Loading } from "../components/States";
import RiskBadge from "../components/RiskBadge";
import { formatDate } from "../utils/format";

const PAGE_SIZE = 12;

export default function History() {
  const [data, setData] = useState<ScanPage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [query, setQuery] = useState("");
  const [classification, setClassification] = useState("");
  const [scanType, setScanType] = useState("");

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setPage(1);
      setQuery(search.trim());
    }, 350);
    return () => window.clearTimeout(timer);
  }, [search]);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError(null);
    api
      .listScans({
        page,
        page_size: PAGE_SIZE,
        search: query || undefined,
        classification: classification || undefined,
        scan_type: scanType || undefined,
      })
      .then((value) => {
        if (active) setData(value);
      })
      .catch((err: unknown) => {
        if (active) {
          setError(err instanceof ApiError ? err.message : "Failed to load scan history.");
        }
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [page, query, classification, scanType]);

  const filtersActive = Boolean(query || classification || scanType);

  return (
    <div>
      <PageHeader
        eyebrow="Audit trail"
        title="Scan History"
        description="Stored analyses with their final risk score, verdict and evidence count. Full email bodies are not stored."
        actions={
          <>
            <Link to="/email" className="btn-ghost">
              Email scan
            </Link>
            <Link to="/url" className="btn-primary">
              URL scan
            </Link>
          </>
        }
      />

      <div className="panel p-4">
        <div className="grid gap-3 sm:grid-cols-[1fr_170px_150px]">
          <div className="relative">
            <Search size={15} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
            <input
              className="input pl-9"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search summary or explanation…"
            />
          </div>
          <select
            className="input"
            value={classification}
            onChange={(event) => {
              setClassification(event.target.value);
              setPage(1);
            }}
            aria-label="Filter by classification"
          >
            <option value="">All verdicts</option>
            <option value="safe">Safe</option>
            <option value="suspicious">Suspicious</option>
            <option value="phishing">Phishing</option>
          </select>
          <select
            className="input"
            value={scanType}
            onChange={(event) => {
              setScanType(event.target.value);
              setPage(1);
            }}
            aria-label="Filter by scan type"
          >
            <option value="">All types</option>
            <option value="email">Email</option>
            <option value="url">URL</option>
          </select>
        </div>
        <div className="mt-2 flex items-center gap-2 text-[11px] text-muted">
          <Filter size={12} />
          {data ? `${data.total} matching scan(s)` : "Loading…"}
          {filtersActive && (
            <button
              type="button"
              className="ml-1 text-accent hover:underline"
              onClick={() => {
                setSearch("");
                setClassification("");
                setScanType("");
              }}
            >
              clear filters
            </button>
          )}
        </div>
      </div>

      <div className="mt-4">
        {loading && <Loading label="Loading scans…" />}
        {!loading && error && <ErrorState message={error} />}
        {!loading && !error && data && data.items.length === 0 && (
          <EmptyState
            title={filtersActive ? "No scans match these filters" : "No scans stored yet"}
            description={
              filtersActive
                ? "Try clearing the search or filters to see the full history."
                : "Run an email or URL scan and it will appear here with its evidence."
            }
            action={
              !filtersActive ? (
                <Link to="/url" className="btn-primary">
                  Run a scan
                </Link>
              ) : undefined
            }
          />
        )}

        {!loading && !error && data && data.items.length > 0 && (
          <div className="panel overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full min-w-[720px] text-sm">
                <thead>
                  <tr className="border-b border-line text-left text-[10px] uppercase tracking-[0.14em] text-muted">
                    <th className="px-4 py-3 font-semibold">#</th>
                    <th className="px-4 py-3 font-semibold">Input</th>
                    <th className="px-4 py-3 font-semibold">Type</th>
                    <th className="px-4 py-3 font-semibold">Risk</th>
                    <th className="px-4 py-3 font-semibold">Verdict</th>
                    <th className="px-4 py-3 font-semibold">Confidence</th>
                    <th className="px-4 py-3 font-semibold">Signals</th>
                    <th className="px-4 py-3 text-right font-semibold">Scanned</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {data.items.map((scan) => (
                    <tr key={scan.id} className="group transition hover:bg-panel-2/40">
                      <td className="px-4 py-3 font-mono text-xs text-muted">
                        <Link to={`/history/${scan.id}`} className="hover:text-accent">
                          #{scan.id}
                        </Link>
                      </td>
                      <td className="max-w-[300px] px-4 py-3">
                        <Link
                          to={`/history/${scan.id}`}
                          className="block truncate text-ink transition group-hover:text-accent"
                          title={scan.input_summary}
                        >
                          {scan.input_summary}
                        </Link>
                      </td>
                      <td className="px-4 py-3 text-xs capitalize text-muted">{scan.scan_type}</td>
                      <td className="px-4 py-3 font-mono font-semibold text-ink">{scan.risk_score}</td>
                      <td className="px-4 py-3">
                        <RiskBadge classification={scan.classification} size="sm" />
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-muted">
                        {scan.model_confidence === null
                          ? "—"
                          : `${Math.round(scan.model_confidence * 1000) / 10}%`}
                      </td>
                      <td className="px-4 py-3 text-xs text-muted">{scan.indicator_count}</td>
                      <td className="px-4 py-3 text-right text-[11px] text-muted">
                        {formatDate(scan.created_at)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3 border-t border-line px-4 py-3 text-xs text-muted">
              <span className="flex items-center gap-1.5">
                <HistoryIcon size={13} />
                Page {data.page} of {Math.max(1, data.pages)} · {data.total} total
              </span>
              <div className="flex gap-2">
                <button
                  type="button"
                  className="btn-ghost px-3 py-1.5 text-xs"
                  disabled={data.page <= 1}
                  onClick={() => setPage((value) => Math.max(1, value - 1))}
                >
                  <ChevronLeft size={14} /> Previous
                </button>
                <button
                  type="button"
                  className="btn-ghost px-3 py-1.5 text-xs"
                  disabled={data.page >= data.pages}
                  onClick={() => setPage((value) => value + 1)}
                >
                  Next <ChevronRight size={14} />
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
