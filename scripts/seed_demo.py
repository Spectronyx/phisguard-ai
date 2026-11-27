"""Populate the demo database with real analyses through the public API.

This script does not insert rows directly: every record is produced by the
running FastAPI backend via /api/v1/analyze/*, so the stored risk scores,
components and indicators are genuine model/rule outputs.

Usage:
    python scripts/seed_demo.py [--base-url URL] [--output PATH]

The backend must already be running (see README).
"""

from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "docs" / "demo_results.json"

PHISH_EMAIL = {
    "subject": "URGENT: Your SBI account will be suspended",
    "body": (
        "Dear Customer,\n\nWe detected unauthorized access to your account. You must verify "
        "your account within 24 hours or it will be permanently suspended. Enter your password "
        "and OTP at http://sbi-secure-login.xyz/verify to restore access.\n\n"
        "Failure to comply will result in legal action."
    ),
    "sender": "SBI Support <alerts@sbi-verify.xyz>",
}

LEGIT_EMAIL = {
    "subject": "CS473 project review schedule",
    "body": (
        "Hi Rajneesh,\n\nThe project review is on Friday at 3 PM in Lab 4. Please bring the "
        "current report and demo. Let me know if the time does not work.\n\nRegards,\nDr. Sharma"
    ),
    "sender": "sharma@university.edu",
}

INVOICE_LURE = {
    "subject": "Invoice INV-88421 payment overdue",
    "body": (
        "Dear customer,\n\nPlease find the attached invoice. A payment of USD 4,850 is required "
        "immediately by bank transfer. Open the attached invoice.html to view the beneficiary "
        "details. This is confidential; do not tell anyone.\n\nContact support@docusign-billing.top."
    ),
    "sender": "billing@docusign-billing.top",
}

SUSPICIOUS_INVOICE = {
    "subject": "Your invoice is ready",
    "body": (
        "Hi, your monthly invoice is now available in the billing portal. "
        "Please review it at your convenience."
    ),
    "sender": "billing@company.com",
}

SUSPICIOUS_DELIVERY = {
    "subject": "Package delivery update",
    "body": (
        "Your parcel could not be delivered today. Reschedule delivery using the link in your "
        "account, or contact the local depot."
    ),
    "sender": "noreply@delivery.example.com",
}

SCENARIOS: list[dict] = [
    {"name": "legit_email", "kind": "email", "payload": LEGIT_EMAIL,
     "note": "Legitimate internal email; should stay low risk."},
    {"name": "suspicious_invoice_email", "kind": "email", "payload": SUSPICIOUS_INVOICE,
     "note": "Ordinary invoice reminder; model is uncertain, so it lands in the suspicious band."},
    {"name": "suspicious_delivery_email", "kind": "email", "payload": SUSPICIOUS_DELIVERY,
     "note": "Delivery wording triggers the email model but not the rules."},
    {"name": "phish_email_sbi", "kind": "email", "payload": PHISH_EMAIL,
     "note": "Credential phishing with brand impersonation, OTP request and a lookalike link."},
    {"name": "phish_email_invoice", "kind": "email", "payload": INVOICE_LURE,
     "note": "Invoice lure with attachment bait and a lookalike sender domain."},
    {"name": "benign_url_google", "kind": "url", "payload": {"url": "https://www.google.com/"},
     "note": "Popular bare domain; popularity calibration applies."},
    {"name": "benign_url_github", "kind": "url",
     "payload": {"url": "https://github.com/microsoft/vscode"},
     "note": "Deep link on a popular domain; path is not treated as malicious by itself."},
    {"name": "benign_url_wikipedia", "kind": "url",
     "payload": {"url": "https://en.wikipedia.org/wiki/Phishing"},
     "note": "Reference page about phishing."},
    {"name": "benign_url_python_docs", "kind": "url",
     "payload": {"url": "https://docs.python.org/3/library/urllib.parse.html"},
     "note": "Documentation link with a long path."},
    {"name": "phish_url_oortech", "kind": "url",
     "payload": {"url": (
         "https://adobe-reader-283901.standard.us-east-1.oortech.com/documents.org"
         "?778780533c3344e3709mnv708b00a077878053"
     )},
     "note": "Brand token in a subdomain, hyphenated host and a long encoded query."},
    {"name": "phish_url_paypal", "kind": "url",
     "payload": {"url": "http://paypal-secure-login.xyz/verify-account"},
     "note": "Classic brand-lookalike domain with a credential keyword."},
    {"name": "phish_url_microsoft", "kind": "url",
     "payload": {"url": "http://microsoft-support-helpdesk.xyz"},
     "note": "Brand lookalike on a high-abuse TLD."},
]


def post(base_url: str, kind: str, payload: dict) -> dict:
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/api/v1/analyze/{kind}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(response.read().decode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    records = []
    for scenario in SCENARIOS:
        try:
            result = post(args.base_url, scenario["kind"], scenario["payload"])
        except urllib.error.URLError as exc:
            print(f"ERROR: could not reach the backend at {args.base_url}: {exc}")
            print("Start it with: cd backend && ../.venv/bin/uvicorn app.main:app --port 8000")
            return 1
        summary = {
            "name": scenario["name"],
            "note": scenario["note"],
            "kind": scenario["kind"],
            "scan_id": result["scan_id"],
            "input_summary": result["input_summary"],
            "classification": result["classification"],
            "risk_level": result["risk_level"],
            "risk_score": result["risk_score"],
            "model_confidence": result["model_confidence"],
            "components": [
                {
                    "name": component["name"],
                    "status": component["status"],
                    "score": component["score"],
                    "confidence": component["confidence"],
                    "weight": component["weight"],
                    "contribution": component["contribution"],
                }
                for component in result["components"]
            ],
            "indicators": [indicator["name"] for indicator in result["indicators"]],
            "recommendation": result["recommendation"],
        }
        records.append(summary)
        print(
            f"{scenario['name']:28s} scan #{result['scan_id']:<3d} "
            f"{result['risk_score']:>3d} {result['classification']:<10s} "
            f"({len(result['indicators'])} indicators)"
        )

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "base_url": args.base_url,
        "note": (
            "Every record below was produced by the real PhishGuard API on the stated date. "
            "No numbers are hand-written. Scores may differ slightly if models are retrained."
        ),
        "scenarios": records,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"\nWrote {args.output}")
    print(f"Seeded {len(records)} real scans.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
