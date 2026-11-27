import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft } from "lucide-react";
import { api, ApiError } from "../services/api";
import type { AnalysisResult } from "../types/api";
import { PageHeader } from "../components/Primitives";
import { ErrorState, Loading } from "../components/States";
import ResultView from "../components/ResultView";

export default function ScanDetail() {
  const { id } = useParams<{ id: string }>();
  const scanId = Number(id);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError(null);
    if (!Number.isFinite(scanId) || scanId <= 0) {
      setError("Invalid scan identifier.");
      setLoading(false);
      return;
    }
    api
      .getScan(scanId)
      .then((value) => {
        if (active) setResult(value);
      })
      .catch((err: unknown) => {
        if (active) {
          setError(
            err instanceof ApiError
              ? err.status === 404
                ? "This scan does not exist."
                : err.message
              : "Failed to load the scan.",
          );
        }
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [scanId]);

  return (
    <div>
      <PageHeader
        eyebrow="Stored analysis"
        title={result ? `Scan #${result.scan_id}` : "Scan detail"}
        description="The persisted result, reconstructed from the scan record and its stored indicators. The original full email body is not available."
        actions={
          <Link to="/history" className="btn-ghost">
            <ArrowLeft size={15} /> Back to history
          </Link>
        }
      />

      {loading && <Loading label="Loading scan…" />}
      {!loading && error && <ErrorState message={error} />}
      {!loading && !error && result && <ResultView result={result} />}
    </div>
  );
}
