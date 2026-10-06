#!/usr/bin/env python3
"""
DorkX — Automated OSINT Dork Recon & Live Empty Result Filter
Reconnaissance Search Query Generator, Live 0-Result Filter & Browser Launcher.
"""

import argparse
import html
import gzip
import io
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

VERSION = "1.0.0"
DEFAULT_DORK_FILE = "dorks.txt"
DEFAULT_PLACEHOLDER = "example.com"
DEFAULT_DELAY = 1.5
DEFAULT_VERIFY_DELAY = 2.0

BANNER = r"""
  ____             _     __  __
 |  _ \  ___  _ __| | __ \ \/ /
 | | | |/ _ \| '__| |/ /  \  / 
 | |_| | (_) | |  |   <   /  \ 
 |____/ \___/|_|  |_|\_\ /_/\_\  v1.0.0
 Advanced OSINT Dork Recon & Live 0-Result Filter
"""

SEARCH_ENGINES = {
    "google": "https://www.google.com/search?q={query}",
    "bing": "https://www.bing.com/search?q={query}",
    "duckduckgo": "https://html.duckduckgo.com/html/?q={query}",
    "startpage": "https://www.startpage.com/sp/search?query={query}",
    "yahoo": "https://search.yahoo.com/search?p={query}",
}

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# Signatures for 0-result pages across engines
EMPTY_RESULT_SIGNATURES = [
    "did not match any documents",
    "did not match any search results",
    "Your search -",
    "No results found for",
    "There are no results for",
    "No results were found for",
    "We did not find results for",
    "No results found",
    "no results for",
    "Your search did not return any results",
    "It looks like there aren't any matches for your search",
]

CAPTCHA_SIGNATURES = [
    "detected unusual traffic",
    "our systems have detected unusual traffic",
    "g-recaptcha",
    "hcaptcha",
    "cf-browser-verification",
    "Please verify you are a human",
]


@dataclass
class VerificationResult:
    status: str  # 'HIT', 'EMPTY', 'BLOCKED', 'ERROR'
    query: str
    url: str
    message: str


def clean_domain(raw_input: str) -> str:
    """Extract clean hostname from raw input (handles full URLs, paths, ports, protocols)."""
    cleaned = raw_input.strip()
    if not cleaned:
        raise ValueError("Domain cannot be empty.")

    if not re.match(r"^[a-zA-Z]+://", cleaned):
        parsed = urllib.parse.urlparse(f"http://{cleaned}")
    else:
        parsed = urllib.parse.urlparse(cleaned)

    domain = parsed.hostname or cleaned
    domain = domain.split(":")[0].strip().lower()
    return domain


def load_dorks(filepath: Path) -> List[str]:
    """Load dork queries from file, filtering empty lines and comments."""
    if not filepath.exists():
        raise FileNotFoundError(f"Dork file not found: {filepath.resolve()}")

    try:
        content = filepath.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        content = filepath.read_text(encoding="latin-1")

    dorks = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        dorks.append(line)

    return dorks


def check_query_result(
    query: str,
    url: str,
    timeout: float = 8.0,
    user_agent: str = DEFAULT_USER_AGENT
) -> VerificationResult:
    """
    Sends an HTTP request to the search engine to inspect if results matched documents.
    Detects 'did not match any documents' or zero matches.
    """
    headers = {
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
    }

    req = urllib.request.Request(url, headers=headers)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            body_bytes = response.read()

            # Handle gzip encoding if compressed
            if response.info().get("Content-Encoding") == "gzip":
                try:
                    body_bytes = gzip.GzipFile(fileobj=io.BytesIO(body_bytes)).read()
                except Exception:
                    pass

            try:
                html_text = body_bytes.decode("utf-8", errors="replace")
            except Exception:
                html_text = body_bytes.decode("latin-1", errors="replace")

            # 1. Check for Bot Block / CAPTCHA
            for captcha_sig in CAPTCHA_SIGNATURES:
                if captcha_sig.lower() in html_text.lower():
                    return VerificationResult(
                        status="BLOCKED",
                        query=query,
                        url=url,
                        message="CAPTCHA / Bot challenge detected"
                    )

            # 2. Check for Empty Result Signatures ("did not match any documents")
            for empty_sig in EMPTY_RESULT_SIGNATURES:
                if empty_sig.lower() in html_text.lower():
                    return VerificationResult(
                        status="EMPTY",
                        query=query,
                        url=url,
                        message=f"Zero matches found ('{empty_sig}')"
                    )

            # 3. Valid Results Found
            return VerificationResult(
                status="HIT",
                query=query,
                url=url,
                message="Valid search results found"
            )

    except urllib.error.HTTPError as err:
        if err.code == 429:
            return VerificationResult(
                status="BLOCKED",
                query=query,
                url=url,
                message="HTTP 429 Too Many Requests (Rate Limited)"
            )
        return VerificationResult(
            status="ERROR",
            query=query,
            url=url,
            message=f"HTTP {err.code}: {err.reason}"
        )
    except Exception as err:
        return VerificationResult(
            status="ERROR",
            query=query,
            url=url,
            message=f"Request failed: {err}"
        )


def verify_dorks_pipeline(
    query_list: List[Tuple[str, str]],
    verify_delay: float = DEFAULT_VERIFY_DELAY,
    max_verify: int = 0,
    keep_blocked: bool = True
) -> Tuple[List[Tuple[str, str]], dict]:
    """
    Runs live verification to filter out empty zero-match results.
    """
    total = len(query_list) if max_verify <= 0 else min(len(query_list), max_verify)
    print(f"\n[*] Starting live result verification for {total} queries (Delay: {verify_delay}s)...")
    print("[*] Queries with 'did not match any documents' will be strictly EXCLUDED from report.\n")

    verified_hits: List[Tuple[str, str]] = []
    stats = {"checked": 0, "hits": 0, "empty": 0, "blocked": 0, "errors": 0}
    blocked_consecutive = 0

    try:
        for i in range(total):
            query, url = query_list[i]
            stats["checked"] += 1

            result = check_query_result(query, url)

            if result.status == "HIT":
                verified_hits.append((query, url))
                stats["hits"] += 1
                blocked_consecutive = 0
                print(f"  [{stats['checked']:03d}/{total:03d}] \033[92m[HIT]\033[0m {query}")

            elif result.status == "EMPTY":
                stats["empty"] += 1
                blocked_consecutive = 0
                print(f"  [{stats['checked']:03d}/{total:03d}] \033[90m[SKIPPED - 0 RESULTS]\033[0m {query}")

            elif result.status == "BLOCKED":
                stats["blocked"] += 1
                blocked_consecutive += 1
                print(f"  [{stats['checked']:03d}/{total:03d}] \033[93m[RATE LIMITED / CAPTCHA]\033[0m {query} ({result.message})")
                if keep_blocked:
                    verified_hits.append((query, url))

                if blocked_consecutive >= 3:
                    print("\n[!] Warning: 3 consecutive requests triggered CAPTCHA / Rate Limit.")
                    print("[!] Search engine is rate-limiting live checks.")
                    choice = input("[?] Continue verifying remaining queries? [y/N]: ").strip().lower()
                    if choice != "y":
                        print("[-] Halting verification. Saving collected hits.")
                        break

            else:  # ERROR
                stats["errors"] += 1
                blocked_consecutive = 0
                print(f"  [{stats['checked']:03d}/{total:03d}] \033[91m[ERROR]\033[0m {query} ({result.message})")
                if keep_blocked:
                    verified_hits.append((query, url))

            if i < total - 1:
                time.sleep(verify_delay)

    except KeyboardInterrupt:
        print("\n[!] Verification paused by user (Ctrl+C). Generating report for verified hits so far.")

    print(f"\n[+] Verification Complete: {stats['hits']} Active Hits | {stats['empty']} Filtered Out | {stats['blocked']} Blocked | {stats['errors']} Errors")
    return verified_hits, stats


def generate_html_report(
    domain: str,
    queries: List[Tuple[str, str]],
    output_path: Path,
    stats: Optional[dict] = None
) -> None:
    """Generates a clickable, styled HTML page containing confirmed search queries."""
    stats_html = ""
    if stats:
        stats_html = f"""
        <div class="stats-bar">
            <span class="stat-pill stat-hit">Active Hits: {stats.get('hits', len(queries))}</span>
            <span class="stat-pill stat-empty">Filtered (0 Results): {stats.get('empty', 0)}</span>
            <span class="stat-pill">Total Inspected: {stats.get('checked', len(queries))}</span>
        </div>
        """
    else:
        stats_html = f"""
        <div class="stats">Total Queries: {len(queries)} &bull; Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}</div>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DorkX Recon Report &mdash; {html.escape(domain)}</title>
    <style>
        :root {{
            --bg-color: #0d1117;
            --card-bg: #161b22;
            --border-color: #30363d;
            --text-color: #c9d1d9;
            --text-muted: #8b949e;
            --accent: #58a6ff;
            --accent-hover: #79c0ff;
            --code-bg: #0f141c;
            --hit-color: #7ee787;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 24px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 960px;
            margin: 0 auto;
        }}
        header {{
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 16px;
            margin-bottom: 24px;
        }}
        .brand {{
            font-size: 1.1rem;
            font-weight: 700;
            color: var(--accent);
            letter-spacing: 1px;
            margin-bottom: 4px;
        }}
        h1 {{
            color: #ffffff;
            margin: 4px 0 10px 0;
            font-size: 1.8rem;
        }}
        .badge {{
            display: inline-block;
            background: rgba(88, 166, 255, 0.15);
            color: var(--accent);
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.9rem;
            font-weight: 600;
        }}
        .stats-bar {{
            margin-top: 14px;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }}
        .stat-pill {{
            background: #21262d;
            padding: 5px 12px;
            border-radius: 6px;
            font-size: 0.85rem;
            color: var(--text-color);
            border: 1px solid var(--border-color);
        }}
        .stat-hit {{
            color: #7ee787;
            border-color: rgba(126, 231, 135, 0.3);
            background: rgba(46, 160, 67, 0.15);
            font-weight: bold;
        }}
        .stat-empty {{
            color: #8b949e;
            border-color: rgba(139, 148, 158, 0.2);
        }}
        .dork-card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 14px 18px;
            margin-bottom: 12px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            transition: border-color 0.2s, box-shadow 0.2s;
        }}
        .dork-card:hover {{
            border-color: var(--accent);
            box-shadow: 0 0 12px rgba(88, 166, 255, 0.12);
        }}
        .dork-query {{
            font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", Menlo, monospace;
            background: var(--code-bg);
            padding: 8px 12px;
            border-radius: 6px;
            color: var(--hit-color);
            font-size: 0.92rem;
            word-break: break-all;
            margin-right: 14px;
            flex-grow: 1;
        }}
        .dork-link {{
            background: #238636;
            color: white;
            padding: 6px 14px;
            border-radius: 6px;
            text-decoration: none;
            font-weight: 600;
            font-size: 0.88rem;
            white-space: nowrap;
            transition: background 0.2s;
        }}
        .dork-link:hover {{
            background: #2ea043;
        }}
        .empty-state {{
            text-align: center;
            padding: 48px;
            color: var(--text-muted);
            background: var(--card-bg);
            border-radius: 8px;
            border: 1px dashed var(--border-color);
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="brand">DORKX &bull; OSINT RECON</div>
            <h1>Verified Dork Matches</h1>
            <span class="badge">Target: {html.escape(domain)}</span>
            {stats_html}
        </header>
        <div class="list">
"""
    if not queries:
        html_content += """            <div class="empty-state">
                <h3>No Active Matching Results</h3>
                <p>All dork queries returned zero documents ("did not match any documents").</p>
            </div>\n"""
    else:
        for i, (query, url) in enumerate(queries, 1):
            html_content += f"""            <div class="dork-card">
                <span style="color: var(--text-muted); margin-right: 14px; font-weight: bold;">{i}.</span>
                <span class="dork-query">{html.escape(query)}</span>
                <a href="{html.escape(url)}" target="_blank" rel="noopener noreferrer" class="dork-link">Open Search &rarr;</a>
            </div>\n"""

    html_content += """        </div>
    </div>
</body>
</html>
"""
    output_path.write_text(html_content, encoding="utf-8")


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        prog="dorkx",
        description="DorkX — Multi-Engine OSINT Dork Recon & Live Empty Result Filter.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Filter out all 'did not match any documents' 0-result queries & generate clean HTML report:
  python dorkx.py target.com --filter-empty --html-report verified_hits.html

  # Verify first 20 dorks with 2s delay:
  python dorkx.py target.com -f dorks.txt --filter-empty --max-verify 20

  # Standard dry run without live HTTP verification:
  python dorkx.py target.com --dry-run
        """
    )

    parser.add_argument(
        "domain",
        help="Target domain or URL (e.g. example.com, https://target.org/path)"
    )

    parser.add_argument(
        "-f",
        "--file",
        default=DEFAULT_DORK_FILE,
        help=f"File containing dork templates (default: '{DEFAULT_DORK_FILE}')"
    )

    parser.add_argument(
        "-p",
        "--placeholder",
        default=DEFAULT_PLACEHOLDER,
        help=f"Placeholder string to replace in templates (default: '{DEFAULT_PLACEHOLDER}')"
    )

    parser.add_argument(
        "-d",
        "--delay",
        type=float,
        default=DEFAULT_DELAY,
        help=f"Delay in seconds between opening browser tabs (default: {DEFAULT_DELAY}s)"
    )

    parser.add_argument(
        "-e",
        "--engine",
        choices=list(SEARCH_ENGINES.keys()),
        default="google",
        help="Search engine to use (default: google)"
    )

    parser.add_argument(
        "-V",
        "--filter-empty",
        action="store_true",
        help="Perform live HTTP check and EXCLUDE queries returning 'did not match any documents' (0 results)"
    )

    parser.add_argument(
        "--verify-delay",
        type=float,
        default=DEFAULT_VERIFY_DELAY,
        help=f"Delay in seconds between live verification requests (default: {DEFAULT_VERIFY_DELAY}s)"
    )

    parser.add_argument(
        "--max-verify",
        type=int,
        default=0,
        help="Max number of queries to verify in live mode (0 = all queries in file)"
    )

    parser.add_argument(
        "--keep-blocked",
        action="store_true",
        default=True,
        help="Retain queries if rate limited/CAPTCHA occurs during verification (default: True)"
    )

    parser.add_argument(
        "-n",
        "--dry-run",
        action="store_true",
        help="Print prepared queries/URLs without opening browser tabs"
    )

    parser.add_argument(
        "-b",
        "--batch-size",
        type=int,
        default=0,
        help="Open dorks in batches of N tabs and prompt before continuing (0 = all at once)"
    )

    parser.add_argument(
        "--html-report",
        metavar="PATH",
        help="Export all matching queries as a clickable HTML report file"
    )

    parser.add_argument(
        "--export-urls",
        metavar="PATH",
        help="Export raw search URLs line-by-line to a text file"
    )

    parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="Skip confirmation prompt when opening > 10 tabs"
    )

    args = parser.parse_args()

    # 1. Clean & validate domain
    try:
        domain = clean_domain(args.domain)
    except ValueError as err:
        print(f"[-] Error: {err}", file=sys.stderr)
        sys.exit(1)

    # 2. Load dorks
    dork_file = Path(args.file)
    try:
        raw_dorks = load_dorks(dork_file)
    except Exception as err:
        print(f"[-] Error loading dork file: {err}", file=sys.stderr)
        sys.exit(1)

    if not raw_dorks:
        print(f"[-] No valid dorks found in '{args.file}'.", file=sys.stderr)
        sys.exit(1)

    # 3. Prepare queries and URLs
    engine_template = SEARCH_ENGINES[args.engine]
    query_list: List[Tuple[str, str]] = []

    for dork in raw_dorks:
        query = dork.replace(args.placeholder, domain)
        encoded_query = urllib.parse.quote_plus(query)
        search_url = engine_template.format(query=encoded_query)
        query_list.append((query, search_url))

    # 4. Display Overview
    print("=" * 65)
    print(f"[*] Target Domain   : {domain}")
    print(f"[*] Total Queries   : {len(query_list)}")
    print(f"[*] Search Engine   : {args.engine.capitalize()}")
    print(f"[*] Filter 0-Result : {'ENABLED (--filter-empty)' if args.filter_empty else 'DISABLED'}")
    print(f"[*] Template File   : {dork_file.resolve()}")
    print("=" * 65)

    stats = None

    # 5. Execute Live Empty-Result Verification (if --filter-empty is set)
    if args.filter_empty:
        query_list, stats = verify_dorks_pipeline(
            query_list,
            verify_delay=args.verify_delay,
            max_verify=args.max_verify,
            keep_blocked=args.keep_blocked
        )

    # 6. Handle File Exports (HTML / Text)
    if args.html_report:
        html_path = Path(args.html_report)
        generate_html_report(domain, query_list, html_path, stats=stats)
        print(f"[+] Clean HTML Report generated: {html_path.resolve()}")

    if args.export_urls:
        export_path = Path(args.export_urls)
        export_path.write_text("\n".join(url for _, url in query_list) + "\n", encoding="utf-8")
        print(f"[+] URLs exported: {export_path.resolve()}")

    # 7. Dry run mode
    if args.dry_run:
        print("\n[+] --- FINAL ACTIVE QUERIES ---")
        for i, (query, url) in enumerate(query_list, 1):
            print(f"[{i:02d}] Query : {query}")
            print(f"     URL   : {url}")
        print(f"\n[+] Dry run finished. {len(query_list)} active matching queries ready. 0 tabs opened.")
        return

    if not query_list:
        print("[-] No matching queries to open.")
        return

    # 8. Safety confirmation if opening many tabs
    if len(query_list) > 10 and not args.yes:
        try:
            choice = input(f"\n[?] Warning: About to open {len(query_list)} browser tabs. Proceed? [Y/n]: ").strip().lower()
            if choice and choice != "y":
                print("[-] Aborted by user.")
                return
        except KeyboardInterrupt:
            print("\n[-] Aborted by user.")
            return

    # 9. Open browser tabs with delay and optional batching
    print("\n[*] Opening matching queries in browser...")
    opened = 0
    try:
        for i, (query, url) in enumerate(query_list, 1):
            print(f"[{i:02d}/{len(query_list):02d}] {query}")
            webbrowser.open_new_tab(url)
            opened += 1

            if args.batch_size > 0 and opened % args.batch_size == 0 and i < len(query_list):
                try:
                    input(f"\n[⏸] Batch limit ({args.batch_size}) reached. Press Enter to open next batch...")
                except KeyboardInterrupt:
                    print("\n[-] Interrupted batch execution.")
                    break

            if i < len(query_list):
                time.sleep(args.delay)

    except KeyboardInterrupt:
        print("\n[!] Execution stopped by user (Ctrl+C).")

    print(f"\n[+] Done. Successfully processed {opened}/{len(query_list)} matching queries.")


if __name__ == "__main__":
    main()
