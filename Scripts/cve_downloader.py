#!/usr/bin/env python3
"""
NVD CVE 2.0 full-history downloader (publication-date windowed).

Purpose:
- Download all NVD CVE records via the official NVD Vulnerabilities API (CVE 2.0).
- Avoid scraping the NVD website UI.
- Persist progress so the download can be resumed safely.

Output:
- JSON Lines file (one NVD "vulnerabilities[]" item per line)
- State file to resume (tracks last completed pubEndDate)

Security:
- Do NOT hardcode your API key in this file.
- Provide it via --api-key or the NVD_API_KEY environment variable.

Notes:
- NVD date filters are provided as ISO-8601 timestamps.
- Date windows are chunked (default 120 days) to comply with typical NVD constraints.
- Pagination uses startIndex/resultsPerPage (max resultsPerPage is 2000).
"""

from __future__ import annotations

import argparse
from pathlib import Path
import json
import os
from dotenv import load_dotenv
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, Optional

import requests


NVD_CVE_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_USER_AGENT = "nvd-cve-full-downloader/1.0"


@dataclass(frozen=True)
class DateWindow:
    """
    Publication-date window used for pubStartDate/pubEndDate queries.
    """
    start_utc: datetime
    end_utc: datetime

    def to_params(self) -> Dict[str, str]:
        return {
            "pubStartDate": to_nvd_iso8601(self.start_utc),
            "pubEndDate": to_nvd_iso8601(self.end_utc),
        }


def utc_now() -> datetime:
    """
    Current time in UTC.
    """
    return datetime.now(timezone.utc)


def to_nvd_iso8601(dt: datetime) -> str:
    """
    Convert datetime -> ISO-8601 UTC with 'Z' suffix as commonly accepted by NVD.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_yyyy_mm_dd(date_str: str) -> datetime:
    """
    Parse YYYY-MM-DD into UTC datetime at 00:00:00.
    """
    try:
        d = datetime.strptime(date_str, "%Y-%m-%d")
    except ValueError as e:
        raise ValueError(f"Invalid date '{date_str}'. Expected YYYY-MM-DD.") from e
    return d.replace(tzinfo=timezone.utc)


def load_state(state_path: Path) -> Dict[str, Any]:
    """
    Load state JSON (resume support).
    """
    if not state_path.exists():
        return {}
    return json.loads(state_path.read_text(encoding="utf-8"))


def save_state(state_path: Path, state: Dict[str, Any]) -> None:
    """
    Save state JSON atomically.
    """
    state_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = state_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
    tmp.replace(state_path)


def build_windows(start: datetime, end: datetime, window_days: int) -> Iterator[DateWindow]:
    """
    Build consecutive [start, end] windows of window_days each.
    """
    if window_days <= 0:
        raise ValueError("window_days must be > 0")

    cursor = start
    step = timedelta(days=window_days)

    while cursor < end:
        nxt = min(cursor + step, end)
        yield DateWindow(start_utc=cursor, end_utc=nxt)
        cursor = nxt


def request_with_retries(
    session: requests.Session,
    url: str,
    headers: Dict[str, str],
    params: Dict[str, Any],
    timeout_s: int,
    max_retries: int,
) -> Dict[str, Any]:
    """
    HTTP GET with retries/backoff.

    Key logic:
    - Retries on 429 and 5xx codes.
    - Uses Retry-After if provided.
    - Retries on network errors and JSON decode issues.
    """
    last_err: Optional[Exception] = None

    for attempt in range(1, max_retries + 1):
        try:
            resp = session.get(url, headers=headers, params=params, timeout=timeout_s)

            if resp.status_code == 200:
                return resp.json()

            # Retry on rate-limit and transient server errors
            if resp.status_code in (429, 500, 502, 503, 504):
                retry_after = resp.headers.get("Retry-After")
                if retry_after:
                    try:
                        sleep_s = int(retry_after)
                    except ValueError:
                        sleep_s = 2 * attempt
                else:
                    sleep_s = 2 * attempt

                time.sleep(sleep_s)
                continue

            # Non-retryable error
            resp.raise_for_status()

        except (requests.RequestException, ValueError) as e:
            last_err = e
            time.sleep(2 * attempt)

    raise RuntimeError(f"Request failed after {max_retries} retries. Last error: {last_err}")


def iter_cves_in_pub_window(
    api_key: Optional[str],
    window: DateWindow,
    results_per_page: int,
    timeout_s: int,
    max_retries: int,
    polite_delay_s: float,
) -> Iterator[Dict[str, Any]]:
    """
    Iterate NVD CVE items within a publication-date window, using pagination.
    """
    headers: Dict[str, str] = {"User-Agent": DEFAULT_USER_AGENT}
    if api_key:
        # NVD uses 'apiKey' request header
        headers["apiKey"] = api_key

    start_index = 0
    total_results: Optional[int] = None

    with requests.Session() as session:
        while True:
            params: Dict[str, Any] = {
                **window.to_params(),
                "startIndex": start_index,
                "resultsPerPage": results_per_page,
            }

            payload = request_with_retries(
                session=session,
                url=NVD_CVE_ENDPOINT,
                headers=headers,
                params=params,
                timeout_s=timeout_s,
                max_retries=max_retries,
            )

            vulns = payload.get("vulnerabilities", []) or []
            if total_results is None:
                tr = payload.get("totalResults")
                total_results = tr if isinstance(tr, int) else None

            # Yield only verified CVEs (Analyzed or Modified status)
            # Drop provisional/invalid: Awaiting Analysis, Reserved, Rejected
            for item in vulns:
                cve_data = item.get("cve", {})
                vuln_status = cve_data.get("vulnStatus", "")
                
                # Only keep verified CVEs
                if vuln_status in ("Analyzed", "Modified"):
                    yield item

            # Pagination advance
            got = len(vulns)
            start_index += got

            # Stop conditions
            if got == 0:
                break
            if total_results is not None and start_index >= total_results:
                break

            # Polite delay between pages to reduce 429s
            if polite_delay_s > 0:
                time.sleep(polite_delay_s)


def append_jsonl(path: Path, records: Iterator[Dict[str, Any]]) -> int:
    """
    Append records to a JSONL file (one JSON object per line).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0

    with path.open("a", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            count += 1

    return count


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Download all NVD CVEs via the CVE 2.0 API (publication-date windows).")

    # Key handling
    parser.add_argument(
        "--api-key",
        default=None,
        help="NVD API key (recommended). If omitted, uses env var NVD_API_KEY if present.",
    )

    # Output paths
    parser.add_argument("--out", default="data/nvd_cves_all.jsonl", help="Output JSONL path.")
    parser.add_argument("--state", default="data/nvd_state.json", help="State file for resume support.")

    # Full history controls
    parser.add_argument("--pub-start", default="1999-01-01", help="Start date (YYYY-MM-DD) for full download.")
    parser.add_argument("--pub-end", default=None, help="End date (YYYY-MM-DD). Default: now (UTC).")
    parser.add_argument(
        "--window-days",
        type=int,
        default=120,
        help="Publication-date window size in days (default 120).",
    )

    # Pagination & robustness
    parser.add_argument("--results-per-page", type=int, default=2000, help="Per-request page size (max 2000).")
    parser.add_argument("--timeout", type=int, default=30, help="HTTP timeout seconds.")
    parser.add_argument("--retries", type=int, default=10, help="Max retries per request.")
    parser.add_argument("--delay", type=float, default=0.6, help="Delay between pages (seconds).")

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    # Load .env file if present
    dotenv_path = Path(__file__).parent.parent / ".env"
    if dotenv_path.exists():
        load_dotenv(dotenv_path)

    # Resolve API key from argument, env var, or .env
    api_key = args.api_key or os.environ.get("NVD_API_KEY")

    # Validate resultsPerPage constraint
    if args.results_per_page < 1 or args.results_per_page > 2000:
        print("Error: --results-per-page must be between 1 and 2000.", file=sys.stderr)
        return 2

    out_path = Path(args.out)
    state_path = Path(args.state)

    # Load state for resume
    state = load_state(state_path)

    # Determine start time: resume from last_pub_end if present, else pub-start
    if "last_pub_end" in state:
        # Stored as ISO-8601 Z; convert safely
        start = datetime.fromisoformat(state["last_pub_end"].replace("Z", "+00:00")).astimezone(timezone.utc)
    else:
        start = parse_yyyy_mm_dd(args.pub_start)

    # Determine end time
    if args.pub_end:
        end = parse_yyyy_mm_dd(args.pub_end)
    else:
        end = utc_now()

    if start >= end:
        print("Nothing to do: start >= end.", file=sys.stderr)
        return 0

    # Walk windows and append results
    total_written = 0

    for win in build_windows(start, end, args.window_days):
        records = iter_cves_in_pub_window(
            api_key=api_key,
            window=win,
            results_per_page=args.results_per_page,
            timeout_s=args.timeout,
            max_retries=args.retries,
            polite_delay_s=args.delay,
        )

        written = append_jsonl(out_path, records)
        total_written += written

        # Persist progress after each window so interruptions are safe
        state["last_pub_end"] = to_nvd_iso8601(win.end_utc)
        save_state(state_path, state)

        print(
            f"Wrote {written} CVE items for window "
            f"{to_nvd_iso8601(win.start_utc)} -> {to_nvd_iso8601(win.end_utc)}"
        )

    print(f"Done. Total appended: {total_written}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
