import { NavLink, Outlet, useLocation } from "react-router-dom";
import {
  Activity,
  History,
  Info,
  LayoutDashboard,
  Link2,
  Mail,
  ShieldCheck,
} from "lucide-react";
import { useEffect, useState } from "react";
import { api } from "../services/api";
import type { HealthStatus } from "../types/api";

const navigation = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/email", label: "Email Scanner", icon: Mail },
  { to: "/url", label: "URL Scanner", icon: Link2 },
  { to: "/history", label: "Scan History", icon: History },
  { to: "/about", label: "About & Limits", icon: Info },
];

function StatusDot({ health }: { health: HealthStatus | null }) {
  const ok = health?.status === "ok";
  return (
    <div className="flex items-center gap-2 text-xs text-muted">
      <span
        className={`h-2 w-2 rounded-full ${
          ok ? "bg-safe shadow-[0_0_10px_2px_rgba(52,211,153,0.35)]" : "bg-warn"
        }`}
      />
      <span className="hidden sm:inline">
        {health ? (ok ? "Backend online" : `Backend ${health.status}`) : "Checking backend…"}
      </span>
    </div>
  );
}

export default function Layout() {
  const location = useLocation();
  const [health, setHealth] = useState<HealthStatus | null>(null);

  useEffect(() => {
    let active = true;
    api
      .health()
      .then((value) => {
        if (active) setHealth(value);
      })
      .catch(() => {
        if (active) setHealth(null);
      });
    return () => {
      active = false;
    };
  }, [location.pathname]);

  return (
    <div className="flex min-h-screen">
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-60 flex-col border-r border-line bg-panel/60 backdrop-blur lg:flex">
        <div className="flex items-center gap-3 px-5 py-6">
          <div className="grid h-10 w-10 place-items-center rounded-xl bg-accent/10 text-accent ring-1 ring-accent/30">
            <ShieldCheck size={22} />
          </div>
          <div>
            <p className="text-sm font-bold tracking-wide text-ink">PhishGuard AI</p>
            <p className="text-[11px] uppercase tracking-[0.18em] text-muted">
              Phishing detection
            </p>
          </div>
        </div>

        <nav className="flex-1 space-y-1 px-3">
          {navigation.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                `nav-link ${isActive ? "nav-link-active" : ""}`
              }
            >
              <item.icon size={17} />
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className="border-t border-line p-4">
          <StatusDot health={health} />
          <p className="mt-2 text-[11px] leading-relaxed text-muted/70">
            SIH25159 · AICTE
            <br />
            URLs are parsed as text, never opened.
          </p>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col lg:pl-60">
        <header className="sticky top-0 z-20 border-b border-line bg-canvas/80 backdrop-blur">
          <div className="flex items-center justify-between gap-4 px-4 py-3 sm:px-6">
            <div className="flex items-center gap-3">
              <div className="grid h-8 w-8 place-items-center rounded-lg bg-accent/10 text-accent ring-1 ring-accent/30 lg:hidden">
                <ShieldCheck size={17} />
              </div>
              <p className="text-sm font-semibold lg:hidden">PhishGuard AI</p>
              <div className="hidden items-center gap-2 text-xs text-muted lg:flex">
                <Activity size={14} className="text-accent" />
                Real-time analysis · local models · explainable risk
              </div>
            </div>
            <StatusDot health={health} />
          </div>

          <nav className="flex gap-1 overflow-x-auto px-2 pb-2 lg:hidden">
            {navigation.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) =>
                  `whitespace-nowrap rounded-lg px-3 py-1.5 text-xs font-semibold ${
                    isActive ? "bg-accent/10 text-accent" : "text-muted"
                  }`
                }
              >
                {item.label}
              </NavLink>
            ))}
          </nav>
        </header>

        <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-6 sm:px-6 lg:py-8">
          <Outlet />
        </main>

        <footer className="border-t border-line px-4 py-4 text-[11px] text-muted/70 sm:px-6">
          PhishGuard AI · academic project CSE473 · metrics are from actual local runs.
        </footer>
      </div>
    </div>
  );
}
