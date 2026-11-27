import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  Activity,
  AlertOctagon,
  ArrowRight,
  Gauge,
  Mail,
  ScanLine,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api, ApiError } from "../services/api";
import type { DashboardStats, TrendResponse } from "../types/api";
import { PageHeader, SectionTitle, StatCard } from "../components/Primitives";
import { EmptyState, ErrorState, Loading } from "../components/States";
import RiskBadge from "../components/RiskBadge";
import { formatDate } from "../utils/format";

const COLORS = ["#34d399", "#fbbf24", "#fb7185"];

const tooltipStyle = {
  background: "#0d1420",
  border: "1px solid #1e2a3d",
  borderRadius: 12,
  fontSize: 12,
  color: "#e6edf7",
};

export default function Dashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [trend, setTrend] = useState<TrendResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useMemo(
    () => () => {
      setLoading(true);
      setError(null);
      Promise.all([api.dashboardStats(), api.dashboardTrend(14)])
        .then(([statsValue, trendValue]) => {
          setStats(statsValue);
          setTrend(trendValue);
        })
        .catch((err: unknown) => {
          setError(err instanceof ApiError ? err.message : "Failed to load dashboard data.");
        })
        .finally(() => setLoading(false));
    },
    [],
  );

  useEffect(() => {
    load();
  }, [load]);

  if (loading) return <Loading label="Loading dashboard…" />;
  if (error) return <ErrorState message={error} onRetry={load} />;
  if (!stats) return null;

  const distribution = stats.distribution.map((point, index) => ({
    ...point,
    color: COLORS[index] ?? "#8fa3bf",
  }));
  const detectionRate =
    stats.total_scans > 0
      ? Math.round((stats.phishing_detections / stats.total_scans) * 100)
      : 0;

  return (
    <div>
      <PageHeader
        eyebrow="Security overview"
        title="Dashboard"
        description="Real scan activity from the local PhishGuard database. Every number here is computed from stored analysis results."
        actions={
          <>
            <Link to="/email" className="btn-ghost">
              <Mail size={15} /> Scan email
            </Link>
            <Link to="/url" className="btn-primary">
              <ScanLine size={15} /> Scan URL
            </Link>
          </>
        }
      />

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Total scans" value={stats.total_scans} icon={Activity} hint={`${stats.email_scans} email · ${stats.url_scans} URL`} />
        <StatCard label="Phishing detected" value={stats.phishing_detections} icon={ShieldAlert} accent="text-danger" hint={`${detectionRate}% of all scans`} />
        <StatCard label="Suspicious" value={stats.suspicious_detections} icon={AlertOctagon} accent="text-warn" hint={`${stats.critical_detections} critical risk`} />
        <StatCard label="Average risk" value={stats.average_risk_score.toFixed(1)} icon={Gauge} hint="0–100 aggregated score" />
      </div>

      {stats.total_scans === 0 ? (
        <div className="mt-6">
          <EmptyState
            title="No scans yet"
            description="Run an email or URL scan to populate the dashboard. Charts and statistics appear after the first real analysis."
            action={
              <Link to="/url" className="btn-primary">
                Run the first scan <ArrowRight size={15} />
              </Link>
            }
          />
        </div>
      ) : (
        <>
          <div className="mt-6 grid gap-4 lg:grid-cols-[1.1fr_1.9fr]">
            <section className="panel p-5">
              <SectionTitle title="Classification distribution" hint={`${stats.total_scans} scans`} />
              <div className="grid place-items-center">
                <div className="relative h-56 w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={distribution}
                        dataKey="value"
                        nameKey="name"
                        innerRadius="62%"
                        outerRadius="86%"
                        paddingAngle={3}
                        stroke="none"
                        isAnimationActive={false}
                      >
                        {distribution.map((entry) => (
                          <Cell key={entry.name} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip contentStyle={tooltipStyle} />
                    </PieChart>
                  </ResponsiveContainer>
                  <div className="pointer-events-none absolute inset-0 grid place-content-center text-center">
                    <p className="font-mono text-3xl font-bold text-ink">{stats.total_scans}</p>
                    <p className="text-[10px] uppercase tracking-[0.18em] text-muted">scans</p>
                  </div>
                </div>
                <div className="flex flex-wrap justify-center gap-4 pb-1">
                  {distribution.map((entry) => (
                    <span key={entry.name} className="flex items-center gap-2 text-xs text-muted">
                      <span className="h-2 w-2 rounded-full" style={{ background: entry.color }} />
                      {entry.name} <span className="font-mono text-ink">{entry.value}</span>
                    </span>
                  ))}
                </div>
              </div>
            </section>

            <section className="panel p-5">
              <SectionTitle title="14-day scan trend" hint="scans vs phishing detections" />
              <div className="h-64 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={trend?.points ?? []} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
                    <defs>
                      <linearGradient id="scanFill" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.35} />
                        <stop offset="100%" stopColor="#22d3ee" stopOpacity={0} />
                      </linearGradient>
                      <linearGradient id="phishFill" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#fb7185" stopOpacity={0.32} />
                        <stop offset="100%" stopColor="#fb7185" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid stroke="#1e2a3d" strokeDasharray="3 3" vertical={false} />
                    <XAxis
                      dataKey="date"
                      tick={{ fill: "#8fa3bf", fontSize: 10 }}
                      tickFormatter={(value: string) => value.slice(5)}
                      axisLine={false}
                      tickLine={false}
                    />
                    <YAxis tick={{ fill: "#8fa3bf", fontSize: 10 }} axisLine={false} tickLine={false} allowDecimals={false} />
                    <Tooltip contentStyle={tooltipStyle} labelStyle={{ color: "#8fa3bf" }} />
                    <Area type="monotone" dataKey="scans" name="Scans" stroke="#22d3ee" strokeWidth={2} fill="url(#scanFill)" isAnimationActive={false} />
                    <Area type="monotone" dataKey="phishing" name="Phishing" stroke="#fb7185" strokeWidth={2} fill="url(#phishFill)" isAnimationActive={false} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </section>
          </div>

          <div className="mt-4 grid gap-4 lg:grid-cols-[1.6fr_1fr]">
            <section className="panel p-5">
              <SectionTitle
                title="Recent scans"
                hint={`${stats.safe_detections} safe · ${stats.suspicious_detections} suspicious · ${stats.phishing_detections} phishing`}
              />
              <div className="overflow-x-auto">
                <table className="w-full min-w-[560px] text-sm">
                  <thead>
                    <tr className="border-b border-line text-left text-[10px] uppercase tracking-[0.14em] text-muted">
                      <th className="pb-2 font-semibold">Input</th>
                      <th className="pb-2 font-semibold">Type</th>
                      <th className="pb-2 font-semibold">Risk</th>
                      <th className="pb-2 font-semibold">Verdict</th>
                      <th className="pb-2 text-right font-semibold">When</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line">
                    {stats.recent_scans.map((scan) => (
                      <tr key={scan.id} className="group">
                        <td className="max-w-[260px] py-2.5 pr-3">
                          <Link
                            to={`/history/${scan.id}`}
                            className="block truncate text-ink transition group-hover:text-accent"
                            title={scan.input_summary}
                          >
                            {scan.input_summary}
                          </Link>
                        </td>
                        <td className="py-2.5 pr-3">
                          <span className="text-xs capitalize text-muted">{scan.scan_type}</span>
                        </td>
                        <td className="py-2.5 pr-3 font-mono text-sm font-semibold text-ink">
                          {scan.risk_score}
                        </td>
                        <td className="py-2.5 pr-3">
                          <RiskBadge classification={scan.classification} size="sm" />
                        </td>
                        <td className="py-2.5 text-right text-[11px] text-muted">
                          {formatDate(scan.created_at)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>

            <section className="panel p-5">
              <SectionTitle title="Most frequent indicators" hint="across stored scans" />
              {stats.top_indicators.length === 0 ? (
                <p className="py-8 text-center text-sm text-muted">
                  No indicators recorded yet.
                </p>
              ) : (
                <div className="h-56 w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart
                      data={stats.top_indicators}
                      layout="vertical"
                      margin={{ top: 0, right: 8, left: 0, bottom: 0 }}
                    >
                      <CartesianGrid stroke="#1e2a3d" strokeDasharray="3 3" horizontal={false} />
                      <XAxis type="number" tick={{ fill: "#8fa3bf", fontSize: 10 }} axisLine={false} tickLine={false} allowDecimals={false} />
                      <YAxis
                        type="category"
                        dataKey="name"
                        width={110}
                        tick={{ fill: "#8fa3bf", fontSize: 10 }}
                        axisLine={false}
                        tickLine={false}
                      />
                      <Tooltip contentStyle={tooltipStyle} />
                      <Bar dataKey="count" name="Scans" fill="#22d3ee" radius={[0, 4, 4, 0]} barSize={12} isAnimationActive={false} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
            </section>
          </div>

          <div className="mt-4 flex items-center gap-2 text-[11px] text-muted">
            <ShieldCheck size={13} className="text-safe" />
            LLM-assisted scans: {stats.llm_assisted_scans}. All other analysis is local.
          </div>
        </>
      )}
    </div>
  );
}
