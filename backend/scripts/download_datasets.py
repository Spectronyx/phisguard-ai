"""Download the public datasets used by PhishGuard AI.

Raw data is intentionally not distributed with the repository. Re-running this
script reproduces the dataset snapshot used for training. Sources and licences
are recorded in ``datasets/DATASET_SOURCES.md`` and in the generated metadata.

Usage:
    python backend/scripts/download_datasets.py [--force]
"""

from __future__ import annotations

import argparse
import sys
import urllib.request
from pathlib import Path

RAW_DIR = Path(__file__).resolve().parents[1] / "datasets" / "raw"

SOURCES = [
    (
        "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2",
        "20030228_easy_ham.tar.bz2",
        "SpamAssassin public corpus — easy ham",
    ),
    (
        "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham_2.tar.bz2",
        "20030228_easy_ham_2.tar.bz2",
        "SpamAssassin public corpus — easy ham 2",
    ),
    (
        "https://spamassassin.apache.org/old/publiccorpus/20030228_hard_ham.tar.bz2",
        "20030228_hard_ham.tar.bz2",
        "SpamAssassin public corpus — hard ham",
    ),
    (
        "https://monkey.org/~jose/phishing/phishing-2019",
        "phishing-2019",
        "Nazario phishing corpus 2019 (CC-BY-4.0)",
    ),
    (
        "https://monkey.org/~jose/phishing/phishing-2020",
        "phishing-2020",
        "Nazario phishing corpus 2020 (CC-BY-4.0)",
    ),
    (
        "https://monkey.org/~jose/phishing/phishing-2021",
        "phishing-2021",
        "Nazario phishing corpus 2021 (CC-BY-4.0)",
    ),
    (
        "https://monkey.org/~jose/phishing/phishing-2022",
        "phishing-2022",
        "Nazario phishing corpus 2022 (CC-BY-4.0)",
    ),
    (
        "https://monkey.org/~jose/phishing/phishing-2023",
        "phishing-2023",
        "Nazario phishing corpus 2023 (CC-BY-4.0)",
    ),
    (
        "https://monkey.org/~jose/phishing/phishing-2024",
        "phishing-2024",
        "Nazario phishing corpus 2024 (CC-BY-4.0)",
    ),
    (
        "https://monkey.org/~jose/phishing/phishing-2025",
        "phishing-2025",
        "Nazario phishing corpus 2025 (CC-BY-4.0)",
    ),
    (
        "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip",
        "top-1m.csv.zip",
        "Cisco Umbrella top 1M domain ranking (popularity prior, not a safety list)",
    ),
    (
        "https://www.kaggle.com/api/v1/datasets/download/sid321axn/malicious-urls-dataset",
        "malicious_phish.zip",
        "Malicious URLs Dataset, Kaggle (CC0 1.0); benign + phishing real URLs",
    ),
    (
        "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt",
        "phishing-links-ACTIVE.txt",
        "Phishing.Database active malicious URLs (CC0-1.0)",
    ),
]


def download(url: str, target: Path, force: bool = False) -> None:
    if target.exists() and target.stat().st_size > 0 and not force:
        print(f"[skip] {target.name} ({target.stat().st_size / 1e6:.1f} MB)")
        return
    print(f"[get ] {target.name} <- {url}")
    request = urllib.request.Request(url, headers={"User-Agent": "PhishGuardAI/1.0 (academic project)"})
    with urllib.request.urlopen(request, timeout=180) as response, target.open("wb") as handle:
        while chunk := response.read(1 << 16):
            handle.write(chunk)
    print(f"[ok  ] {target.name} ({target.stat().st_size / 1e6:.1f} MB)")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="re-download existing files")
    args = parser.parse_args()
    RAW_DIR.mkdir(parents=True, exist_ok=True)

    failures = 0
    for url, name, description in SOURCES:
        print(f"\n{description}")
        try:
            download(url, RAW_DIR / name, force=args.force)
        except Exception as exc:
            failures += 1
            print(f"[fail] {name}: {type(exc).__name__}: {exc}", file=sys.stderr)

    if failures:
        print(f"\n{failures} download(s) failed. Build scripts need all sources.", file=sys.stderr)
        return 1
    print("\nAll dataset sources present.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
