import { Link } from "react-router-dom";
import { Compass } from "lucide-react";

export default function NotFound() {
  return (
    <div className="grid min-h-[60vh] place-items-center text-center">
      <div>
        <div className="mx-auto grid h-12 w-12 place-items-center rounded-2xl bg-accent/10 text-accent ring-1 ring-accent/20">
          <Compass size={22} />
        </div>
        <p className="mt-4 font-mono text-3xl font-bold text-ink">404</p>
        <p className="mt-1 text-sm text-muted">This page does not exist in PhishGuard AI.</p>
        <Link to="/" className="btn-primary mt-5">
          Return to dashboard
        </Link>
      </div>
    </div>
  );
}
