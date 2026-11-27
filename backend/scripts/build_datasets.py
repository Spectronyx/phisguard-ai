"""Build reproducible email and URL datasets from raw public corpora.

Outputs (backend/datasets/processed):
- email_dataset.csv     subject, body, label, source, year
- url_dataset.csv       url, label, source
- dataset_metadata.json counts, licences, construction notes, SHA-256 hashes

Datasets:
- Emails: Nazario Phishing Corpus (phishing) vs SpamAssassin public corpus (ham).
- URLs: PhiUSIIL (UCI 967, real legitimate + phishing URLs, CC BY 4.0) plus
  recent malicious URLs from Phishing.Database (CC0-1.0). All URL samples are
  real URLs; no synthetic or constructed URLs are used.

Usage:
    python backend/scripts/build_datasets.py [--email-phishing-cap 6000] [--url-limit 12000]
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import mailbox
import random
import re
import sys
import tarfile
import zipfile
from collections import Counter, defaultdict
from datetime import date
from email import message_from_bytes
from email.header import decode_header, make_header
from email.message import Message
from pathlib import Path
from urllib.parse import urlsplit

import pandas as pd

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))
RAW_DIR = BACKEND_DIR / "datasets" / "raw"
PROCESSED_DIR = BACKEND_DIR / "datasets" / "processed"
SEED = 42

MULTI_SUFFIX = {
    ("co", "in"), ("co", "uk"), ("org", "uk"), ("ac", "uk"), ("gov", "uk"),
    ("com", "au"), ("com", "br"), ("co", "jp"), ("co", "za"), ("com", "sg"),
    ("co", "nz"), ("com", "mx"), ("com", "cn"),
}


def registrable_domain(host: str) -> str:
    host = host.lower().strip(".")
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if len(labels) >= 3 and tuple(labels[-2:]) in MULTI_SUFFIX:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def host_of(url: str) -> str:
    try:
        candidate = url if "://" in url else "http://" + url
        return (urlsplit(candidate).hostname or "").lower().strip(".")
    except ValueError:
        return ""


def decode_header_value(value: str | None) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return str(value)


def extract_body(message: Message) -> str:
    """Extract readable text from a MIME email without attachments."""
    text_parts: list[str] = []
    html_parts: list[str] = []

    for part in message.walk():
        if part.is_multipart():
            continue
        disposition = str(part.get("Content-Disposition", "")).lower()
        if "attachment" in disposition:
            continue
        content_type = part.get_content_type()
        if content_type not in {"text/plain", "text/html"}:
            continue
        try:
            payload = part.get_payload(decode=True)
            if payload is None:
                continue
            charset = part.get_content_charset() or "utf-8"
            decoded = payload.decode(charset, errors="replace")
        except Exception:
            continue
        if content_type == "text/plain":
            text_parts.append(decoded)
        else:
            html_parts.append(decoded)

    body = "\n".join(text_parts).strip()
    if len(body) < 20 and html_parts:
        from app.nlp.features import html_to_text  # reuse the same HTML stripper

        body = html_to_text("\n".join(html_parts)).strip()
    lines = [line for line in body.splitlines() if not line.lstrip().startswith(">")]
    return "\n".join(lines).strip()


def _normalise_for_dedupe(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower()).strip()[:5000]


def load_ham() -> tuple[list[dict], dict]:
    records: list[dict] = []
    stats = Counter()
    for archive_name in ["20030228_easy_ham.tar.bz2", "20030228_easy_ham_2.tar.bz2", "20030228_hard_ham.tar.bz2"]:
        archive = RAW_DIR / archive_name
        if not archive.exists():
            print(f"[warn] missing {archive_name}", file=sys.stderr)
            continue
        with tarfile.open(archive, "r:bz2") as tar:
            for member in tar.getmembers():
                if not member.isfile():
                    continue
                name = Path(member.name).name
                if name.startswith("cmds"):
                    continue
                handle = tar.extractfile(member)
                if handle is None:
                    continue
                message = message_from_bytes(handle.read())
                subject = decode_header_value(message.get("Subject"))
                body = extract_body(message)
                if len(body) < 20:
                    stats["empty"] += 1
                    continue
                records.append({
                    "subject": subject[:500],
                    "body": body[:20_000],
                    "label": 0,
                    "source": f"spamassassin:{archive_name.removeprefix('20030228_').removesuffix('.tar.bz2')}",
                    "year": 2003,
                })
                stats["parsed"] += 1
    return records, dict(stats)


def load_phishing(cap: int) -> tuple[list[dict], dict]:
    records: list[dict] = []
    stats = Counter()
    for year in [2019, 2020, 2021, 2022, 2023, 2024, 2025]:
        path = RAW_DIR / f"phishing-{year}"
        if not path.exists():
            print(f"[warn] missing phishing-{year}", file=sys.stderr)
            continue
        box = mailbox.mbox(path, create=False)
        try:
            for message in box:
                subject = decode_header_value(message.get("Subject"))
                body = extract_body(message)
                if len(body) < 20:
                    stats["empty"] += 1
                    continue
                records.append({
                    "subject": subject[:500],
                    "body": body[:20_000],
                    "label": 1,
                    "source": "nazario_phishing",
                    "year": year,
                })
                stats["parsed"] += 1
        finally:
            box.close()
    rng = random.Random(SEED)
    rng.shuffle(records)
    if len(records) > cap:
        stats["sampled_out"] = len(records) - cap
        records = records[:cap]
    return records, dict(stats)


def dedupe_email(records: list[dict]) -> tuple[list[dict], int]:
    seen: set[str] = set()
    unique: list[dict] = []
    removed = 0
    for record in records:
        key = hashlib.sha1(_normalise_for_dedupe(f"{record['subject']} {record['body']}").encode()).hexdigest()
        if key in seen:
            removed += 1
            continue
        seen.add(key)
        unique.append(record)
    return unique, removed


def load_kaggle_urls() -> tuple[list[dict], list[dict], dict]:
    """Load real benign and phishing URLs from the CC0 Kaggle URL dataset.

    Source: ``malicious_phish.csv`` (Siddhartha, Kaggle, CC0), derived from the
    ISCX-URL-2016 corpus. Labels: benign, phishing, malware, defacement. Only
    benign and phishing rows are used; malware/defacement are out of scope.
    URLs are deduplicated by hostname so no domain appears twice in the dataset.
    """
    path = RAW_DIR / "malicious_phish.zip"
    with zipfile.ZipFile(path) as archive:
        member = next(name for name in archive.namelist() if name.endswith(".csv"))
        frame = pd.read_csv(archive.open(member))
    frame.columns = [str(column).strip().lower() for column in frame.columns]
    frame["url"] = frame["url"].astype(str).str.strip()
    frame = frame[frame["url"].str.len().between(4, 2048)]
    # Many rows in this corpus omit the scheme; normalise without fetching.
    frame["url"] = frame["url"].map(
        lambda value: value if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value) else "http://" + value
    )
    frame = frame[frame["url"].str.match(r"^https?://", case=False)]

    stats = {
        "rows": int(len(frame)),
        "label_distribution": {str(k): int(v) for k, v in frame["type"].value_counts().items()},
        "licence": "CC0 1.0 (Kaggle dataset metadata)",
    }

    def to_records(url_type: str, label: int) -> list[dict]:
        rows = frame[frame["type"] == url_type]
        seen_hosts: set[str] = set()
        records: list[dict] = []
        for url in rows["url"]:
            host = host_of(url)
            if not host or host in seen_hosts:
                continue
            seen_hosts.add(host)
            records.append({"url": url, "label": label, "source": f"kaggle_{url_type}"})
        return records

    benign = to_records("benign", 0)
    phishing = to_records("phishing", 1)
    stats["unique_benign_hosts"] = len(benign)
    stats["unique_phishing_hosts"] = len(phishing)
    return benign, phishing, stats


def load_malicious_feed(count: int, benign_domains: set[str], rng: random.Random) -> tuple[list[dict], dict]:
    """Sample recent malicious URLs from Phishing.Database (real URLs)."""
    path = RAW_DIR / "phishing-links-ACTIVE.txt"
    by_host: dict[str, str] = {}
    stats = Counter()
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            url = line.strip()
            if not url or len(url) > 2048:
                continue
            if not re.match(r"^https?://", url, re.IGNORECASE):
                stats["non_http"] += 1
                continue
            host = host_of(url)
            if not host:
                stats["parse_error"] += 1
                continue
            if registrable_domain(host) in benign_domains:
                stats["benign_domain_conflict"] += 1
                continue
            if host not in by_host:
                by_host[host] = url
    hosts = list(by_host.items())
    rng.shuffle(hosts)
    sample = hosts[:count]
    stats["unique_hosts"] = len(by_host)
    stats["sampled"] = len(sample)
    return [{"url": url, "label": 1, "source": "phishing_database"} for host, url in sample], dict(stats)


def write_csv(path: Path, rows: list[dict], columns: list[str]) -> str:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for row in rows:
            writer.writerow({column: row.get(column, "") for column in columns})
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_url_dataset(limit: int, rng: random.Random) -> tuple[list[dict], dict, dict]:
    benign_pool, phishing_pool, kaggle_stats = load_kaggle_urls()
    rng.shuffle(benign_pool)
    rng.shuffle(phishing_pool)

    # All legitimate registrable domains are used to remove contradictory
    # malicious labels, not just the sampled subset.
    benign_domains = {registrable_domain(host_of(item["url"])) for item in benign_pool}
    benign = benign_pool[:limit]

    kaggle_malicious = [
        item for item in phishing_pool
        if registrable_domain(host_of(item["url"])) not in benign_domains
    ][: limit // 2]

    feed_malicious, feed_stats = load_malicious_feed(limit, benign_domains, rng)
    used_hosts = {host_of(item["url"]) for item in kaggle_malicious}
    feed_malicious = [
        item for item in feed_malicious if host_of(item["url"]) not in used_hosts
    ][: limit - len(kaggle_malicious)]

    malicious = kaggle_malicious + feed_malicious
    used_hosts = {host_of(item["url"]) for item in malicious}
    if len(malicious) < limit:  # top up from remaining Kaggle phishing rows
        for item in phishing_pool:
            if len(malicious) >= limit:
                break
            host = host_of(item["url"])
            if not host or host in used_hosts:
                continue
            if registrable_domain(host) in benign_domains:
                continue
            malicious.append(item)
            used_hosts.add(host)

    benign = benign[:limit]
    records = benign + malicious
    rng.shuffle(records)

    stats = {
        "kaggle": kaggle_stats,
        "phishing_database": feed_stats,
        "benign_real_urls": len(benign),
        "malicious_kaggle": len(kaggle_malicious),
        "malicious_phishing_database": len(feed_malicious),
        "total_malicious": len(malicious),
        "deduplication": "unique hostname per class; contradictory domains removed",
    }
    return records, stats, kaggle_stats


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--email-phishing-cap", type=int, default=6000)
    parser.add_argument("--url-limit", type=int, default=12_000)
    parser.add_argument("--seed", type=int, default=SEED)
    args = parser.parse_args()

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    rng = random.Random(args.seed)

    print("Parsing legitimate email corpus (SpamAssassin)...")
    ham, ham_stats = load_ham()
    print(f"  parsed {len(ham)} ham messages ({ham_stats})")
    print("Parsing phishing email corpus (Nazario)...")
    phishing, phishing_stats = load_phishing(args.email_phishing_cap)
    print(f"  kept {len(phishing)} phishing messages ({phishing_stats})")

    emails, removed = dedupe_email(ham + phishing)
    emails.sort(key=lambda r: (r["label"], r["source"], r["subject"]))
    email_hash = write_csv(PROCESSED_DIR / "email_dataset.csv", emails, ["subject", "body", "label", "source", "year"])
    email_counts = Counter(r["label"] for r in emails)
    print(f"  final email dataset: {len(emails)} rows, removed {removed} duplicates")
    print(f"  label distribution: ham={email_counts[0]}, phishing={email_counts[1]}")

    print("Building URL dataset (Kaggle + Phishing.Database)...")
    urls, url_stats, phi_stats = build_url_dataset(args.url_limit, rng)
    url_hash = write_csv(PROCESSED_DIR / "url_dataset.csv", urls, ["url", "label", "source"])
    url_counts = Counter(r["label"] for r in urls)
    print(f"  final URL dataset: {len(urls)} rows, benign={url_counts[0]}, malicious={url_counts[1]}")
    print(f"  source breakdown: {url_stats}")

    metadata = {
        "generated_on": date.today().isoformat(),
        "seed": args.seed,
        "email": {
            "rows": len(emails),
            "label_distribution": {"legitimate": email_counts[0], "phishing": email_counts[1]},
            "duplicates_removed": removed,
            "sha256": email_hash,
            "sources": [
                {
                    "name": "Nazario Phishing Corpus 2019–2025",
                    "url": "https://monkey.org/~jose/phishing/",
                    "licence": "CC-BY-4.0",
                    "usage": "phishing email class",
                },
                {
                    "name": "SpamAssassin Public Corpus (easy_ham, easy_ham_2, hard_ham)",
                    "url": "https://spamassassin.apache.org/old/publiccorpus/",
                    "licence": "Apache SpamAssassin public corpus terms",
                    "usage": "legitimate email class",
                },
            ],
            "notes": (
                "Emails were parsed from mbox/tar archives, attachments were ignored, HTML was "
                "converted to text, quoted lines were removed, and bodies were truncated to 20,000 "
                "characters. Phishing messages were randomly capped to keep training tractable. "
                "The legitimate corpus is from 2003 while phishing messages span 2019–2025; this "
                "temporal mismatch can inflate measured performance and is disclosed as a limitation."
            ),
        },
        "url": {
            "rows": len(urls),
            "label_distribution": {"benign": url_counts[0], "malicious": url_counts[1]},
            "sha256": url_hash,
            "sources": [
                {
                    "name": "Malicious URLs Dataset (Siddhartha, Kaggle), derived from ISCX-URL-2016",
                    "url": "https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset",
                    "licence": "CC0 1.0 (Kaggle dataset metadata)",
                    "usage": "real benign URLs and real phishing URLs",
                },
                {
                    "name": "Phishing.Database active phishing links (Phishing-Database/Phishing.Database)",
                    "url": "https://github.com/Phishing-Database/Phishing.Database",
                    "licence": "CC0-1.0",
                    "usage": "additional recent real malicious URLs",
                },
            ],
            "notes": (
                "All URL samples are real URLs. The Kaggle dataset's benign and phishing "
                "categories were used (defacement and malware categories were excluded). "
                "Samples are deduplicated to one URL per hostname. Malicious URLs whose "
                "registrable domain also appeared in the full benign pool were excluded to "
                "avoid contradictory labels. Benign corpora are homepage-heavy; because path "
                "features are excluded from the URL ML model, this bias does not drive the "
                "model. No URLs were fetched or opened during dataset construction."
            ),
            "source_breakdown": url_stats,
        },
    }
    (PROCESSED_DIR / "dataset_metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(f"\nWrote {PROCESSED_DIR / 'email_dataset.csv'}")
    print(f"Wrote {PROCESSED_DIR / 'url_dataset.csv'}")
    print(f"Wrote {PROCESSED_DIR / 'dataset_metadata.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
