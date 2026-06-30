#!/usr/bin/env python3
# Evil CSRF - Cross‑Site Request Forgery Detection Tool
# Detects all major CSRF variations: stored, reflected, login, GET/POST,
# content‑type, method‑based, and referrer‑based.

import os
import random
import re
import json
import time
import logging
import sys
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
    use_cookies: bool = True
    threads: int = 5
    test_active: bool = False          # Enable active token validation tests (POST only)
    aggressive: bool = False           # Enable advanced tests (content-type, method, referrer)
    custom_tokens: List[str] = field(default_factory=list)

class Colors:
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD_MAGENTA = "\033[1;95m"
    CYAN = "\033[96m"
    RESET = "\033[0m"

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
    def get(self, url: str, headers: Optional[Dict] = None) -> Optional[requests.Response]:
        time.sleep(self.delay)
        h = DEFAULT_HEADERS.copy()
        h["User-Agent"] = random.choice(USER_AGENTS)
        if headers:
            h.update(headers)
        debug(f"HTTP GET -> {pretty_url(url)}")
        try:
            response = self.session.get(
                url, headers=h, timeout=self.timeout, allow_redirects=True
            )
            debug(f"Status: {response.status_code} | len(body)= {len(response.text)}")
            response.raise_for_status()
            return response
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 403:
                warn(f"Access denied (403) for {pretty_url(url)}")
            else:
                error(f"HTTP Error: {e} for {pretty_url(url)}")
        except requests.exceptions.Timeout:
            error(f"Timeout occurred for {pretty_url(url)}")
        except requests.exceptions.RequestException as e:
            error(f"Request failed: {pretty_url(url)} ({e})")
        return None
    def post(self, url: str, data: Optional[Dict] = None, json_data: Optional[Dict] = None,
             headers: Optional[Dict] = None) -> Optional[requests.Response]:
        time.sleep(self.delay)
        h = DEFAULT_HEADERS.copy()
        h["User-Agent"] = random.choice(USER_AGENTS)
        if headers:
            h.update(headers)
        debug(f"HTTP POST -> {pretty_url(url)} with data {data} json {json_data}")
        try:
            response = self.session.post(
                url, data=data, json=json_data, headers=h, timeout=self.timeout, allow_redirects=True
            )
            debug(f"Status: {response.status_code} | len(body)= {len(response.text)}")
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            error(f"POST request failed: {pretty_url(url)} ({e})")
        return None

# ===========================
# Crawling
# ===========================
@dataclass
class FormInfo:
    action: str
    method: str
    inputs: Dict[str, str]          # name -> default value (if any)
    token_fields: List[str] = field(default_factory=list)
    is_login: bool = False
    is_storage: bool = False

@dataclass
class CrawlResult:
    url: str
    forms: List[FormInfo] = field(default_factory=list)

class Crawler:
    def __init__(self, base_url: str, depth: int = 2, client: Optional[HttpClient] = None,
                 token_names: List[str] = None):
        self.base_url = base_url.rstrip("/")
        self.depth = max(1, depth)
        self.client = client or HttpClient()
        self.visited: Set[str] = set()
        self.results: Dict[str, List[FormInfo]] = {}   # page_url -> list of forms
        self.token_names = token_names or []

    def run(self) -> List[CrawlResult]:
        info(f"Starting crawl on: {self.base_url}")
        self._crawl(self.base_url, self.depth)
        results = []
        for url, forms in self.results.items():
            results.append(CrawlResult(url, forms))
        debug(f"Crawl discovered {len(results)} pages with forms")
        return results

    def _crawl(self, url: str, depth: int) -> None:
        url = normalize_url(url)
        if depth <= 0 or url in self.visited:
            debug(f"Skipping (visited/depth): {url} (depth={depth})")
            return
        self.visited.add(url)
        resp = self.client.get(url)
        if not resp or "text/html" not in (resp.headers.get("Content-Type") or ""):
            debug(f"Non-HTML or no response: {url}")
            return
        soup = BeautifulSoup(resp.text, "html.parser")
        forms_on_page = []
        for form in soup.find_all("form"):
            action = form.get("action")
            if action:
                action_url = urljoin(url, action)
                if not same_domain(action_url, self.base_url):
                    continue
            else:
                action_url = url
            method = form.get("method", "GET").upper()
            inputs = form.find_all(["input", "textarea", "select"])
            input_data = {}
            token_fields = []
            is_login = False
            is_storage = False
            for inp in inputs:
                name = inp.get("name")
                if not name:
                    continue
                default = inp.get("value")
                if default is None and inp.name == "textarea" and inp.string:
                    default = inp.string.strip()
                if default is not None:
                    input_data[name] = default
                # Check if this input looks like a CSRF token
                if self._is_token_field(name):
                    token_fields.append(name)
                # Heuristics for login and storage forms
                name_lower = name.lower()
                if any(kw in name_lower for kw in ["user", "username", "email", "pass", "password", "login"]):
                    is_login = True
                if any(kw in name_lower for kw in ["comment", "message", "post", "content", "body", "text"]):
                    is_storage = True
            # Also check action URL for login hints
            if "login" in action_url.lower():
                is_login = True
            if any(kw in action_url.lower() for kw in ["comment", "post", "message", "save"]):
                is_storage = True

            form_info = FormInfo(
                action=action_url,
                method=method,
                inputs=input_data,
                token_fields=token_fields,
                is_login=is_login,
                is_storage=is_storage
            )
            forms_on_page.append(form_info)
            info(f"Found form at {url} -> action={action_url}, method={method}, token_fields={token_fields}")
        if forms_on_page:
            self.results.setdefault(url, []).extend(forms_on_page)

        # Continue crawling links
        for a in soup.find_all("a", href=True):
            href = a["href"]
            nxt = urljoin(url, href)
            if same_domain(nxt, self.base_url):
                self._crawl(nxt, depth - 1)

    def _is_token_field(self, name: str) -> bool:
        name_lower = name.lower()
        common = [
            "csrf", "csrf_token", "user_token", "authenticity_token",
            "token", "_token", "csrfmiddlewaretoken", "xsrf-token",
            "x-csrf-token", "csrf-token", "security_token", "form_token"
        ]
        all_tokens = set(common) | set(self.token_names)
        for t in all_tokens:
            if t.lower() in name_lower:
                return True
        return False

# ===========================
# CSRF Scanner
# ===========================
@dataclass
class Finding:
    url: str
    form_action: str
    method: str
    token_present: bool
    token_fields: List[str]
    csrf_type: str                     # "GET", "POST", "Login", "Stored", "Content-Type", "Method", "Referrer"
    test_result: Optional[str] = None   # "vulnerable", "protected", "inconclusive"
    severity: str = "Unknown"
    confidence: float = 0.0
    def to_dict(self):
        return {
            "url": self.url,
            "form_action": self.form_action,
            "method": self.method,
            "token_present": self.token_present,
            "token_fields": self.token_fields,
            "csrf_type": self.csrf_type,
            "test_result": self.test_result,
            "severity": self.severity,
            "confidence": self.confidence,
        }

class Scanner:
    STATE_CHANGE_KEYWORDS = [
        "password", "pass", "pwd", "change", "update", "edit", "modify",
        "delete", "remove", "add", "create", "insert", "set", "enable",
        "disable", "activate", "deactivate", "grant", "revoke", "upload",
        "download", "submit", "save", "store", "send", "transfer"
    ]

    def __init__(self, client: Optional[HttpClient] = None, config: Optional[Config] = None):
        self.client = client or HttpClient(timeout=10)
        self.config = config or Config()
        self.findings: List[Finding] = []

    def _is_state_changing_get(self, form: FormInfo) -> bool:
        for name in form.inputs.keys():
            name_lower = name.lower()
            for kw in self.STATE_CHANGE_KEYWORDS:
                if kw in name_lower:
                    return True
        parsed = urlparse(form.action)
        qs = parse_qs(parsed.query)
        for param in qs.keys():
            param_lower = param.lower()
            for kw in self.STATE_CHANGE_KEYWORDS:
                if kw in param_lower:
                    return True
        return False

    def _calculate_severity(self, csrf_type: str, token_present: bool, test_result: Optional[str] = None) -> str:
        if test_result == "vulnerable":
            return "High"
        if not token_present:
            return "High"
        if test_result == "protected":
            return "Low"
        return "Medium"

    def _calculate_confidence(self, csrf_type: str, token_present: bool, test_result: Optional[str] = None) -> float:
        if test_result == "vulnerable":
            return 0.95
        if not token_present:
            return 0.85
        if test_result == "protected":
            return 0.90
        return 0.70

    def _similarity_ratio(self, a: str, b: str) -> float:
        if not a or not b:
            return 0.0
        import difflib
        return difflib.SequenceMatcher(None, a, b).ratio()

    def _test_token_validation(self, form: FormInfo, page_url: str) -> Optional[str]:
        if form.method.upper() != "POST":
            return None
        if not form.inputs:
            return None
        baseline_data = form.inputs.copy()
        token_fields = [f for f in form.inputs if f in form.token_fields]
        if not token_fields:
            return None
        test_data = form.inputs.copy()
        for tf in token_fields:
            test_data[tf] = "EvilCSRF_" + ''.join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=8))
        baseline_resp = self.client.post(form.action, data=baseline_data)
        if not baseline_resp:
            return None
        test_resp = self.client.post(form.action, data=test_data)
        if not test_resp:
            return None
        if baseline_resp.status_code == test_resp.status_code:
            ratio = self._similarity_ratio(baseline_resp.text, test_resp.text)
            error_indicators = ["invalid token", "csrf", "token mismatch", "security token", "form token"]
            test_lower = test_resp.text.lower()
            token_error = any(ind in test_lower for ind in error_indicators)
            if token_error:
                return "protected"
            if ratio > 0.9:
                return "vulnerable"
            else:
                return None
        else:
            return "protected"

    def _test_content_type(self, form: FormInfo) -> Optional[str]:
        if form.method.upper() != "POST" or not form.inputs:
            return None
        # Attempt to send JSON payload with random data (no token)
        json_data = {k: "test" for k in form.inputs.keys()}
        # Remove token fields if present
        for tf in form.token_fields:
            json_data.pop(tf, None)
        # Send without token, with Content-Type: application/json
        headers = {"Content-Type": "application/json"}
        resp = self.client.post(form.action, json_data=json_data, headers=headers)
        if not resp:
            return None
        # If status is 2xx, likely vulnerable; if 4xx, protected
        if 200 <= resp.status_code < 300:
            # Check for error message about unsupported media type
            if "unsupported media" in resp.text.lower():
                return None  # not supported
            return "vulnerable"
        elif 400 <= resp.status_code < 500:
            return "protected"
        else:
            return None

    def _test_method_based(self, form: FormInfo) -> Optional[str]:
        if form.method.upper() != "POST":
            return None
        # Build GET URL with same parameters (if possible)
        if not form.inputs:
            return None
        # Use the same data but send as GET query
        # Remove token fields to test if token is required
        data = {k: v for k, v in form.inputs.items() if k not in form.token_fields}
        parsed = urlparse(form.action)
        qs = parse_qs(parsed.query)
        qs.update(data)
        new_qs = urlencode({k: v[0] if isinstance(v, list) else v for k, v in qs.items()}, doseq=True)
        get_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_qs, ""))
        resp = self.client.get(get_url)
        if not resp:
            return None
        # If status 2xx, likely vulnerable (GET can perform action)
        if 200 <= resp.status_code < 300:
            return "vulnerable"
        elif 400 <= resp.status_code < 500:
            return "protected"
        else:
            return None

    def _test_referrer(self, form: FormInfo) -> Optional[str]:
        if form.method.upper() != "POST" or not form.inputs:
            return None
        # Send POST without Referer
        headers = {"Referer": ""}  # Empty or omit
        resp = self.client.post(form.action, data=form.inputs, headers=headers)
        if not resp:
            return None
        # Compare with baseline with normal referer
        baseline_resp = self.client.post(form.action, data=form.inputs)
        if not baseline_resp:
            return None
        if resp.status_code == baseline_resp.status_code:
            ratio = self._similarity_ratio(baseline_resp.text, resp.text)
            if ratio > 0.9:
                return "vulnerable"
            else:
                return None
        else:
            return "protected"

    def scan_form(self, page_url: str, form: FormInfo) -> List[Finding]:
        findings = []
        diag(f"Scanning form: action={form.action}, method={form.method}")
        is_state_changing = form.method.upper() in ["POST", "PUT", "DELETE"]
        if form.method.upper() == "GET" and self._is_state_changing_get(form):
            is_state_changing = True

        if not is_state_changing and not form.is_login and not form.is_storage:
            debug(f"Skipping non-state-changing method: {form.method}")
            return findings

        token_present = bool(form.token_fields)

        # --- 1. Missing token on state-changing form (Reflected/Stored) ---
        if is_state_changing and not token_present:
            # Determine subtype
            csrf_type = "POST" if form.method.upper() in ["POST", "PUT", "DELETE"] else "GET"
            if form.is_storage:
                csrf_type = "Stored"
            if form.is_login:
                csrf_type = "Login"
            finding = Finding(
                url=page_url,
                form_action=form.action,
                method=form.method,
                token_present=token_present,
                token_fields=form.token_fields,
                csrf_type=csrf_type,
                test_result=None,
                severity="High",
                confidence=0.85
            )
            findings.append(finding)
            warn(f"CSRF vulnerability: no token found on {form.action} (method {form.method})")

        # --- 2. Token present but not validated (only for POST) ---
        if token_present and is_state_changing and form.method.upper() == "POST":
            if self.config.test_active:
                test_result = self._test_token_validation(form, page_url)
                if test_result == "vulnerable":
                    finding = Finding(
                        url=page_url,
                        form_action=form.action,
                        method=form.method,
                        token_present=token_present,
                        token_fields=form.token_fields,
                        csrf_type="POST",
                        test_result="vulnerable",
                        severity="High",
                        confidence=0.95
                    )
                    findings.append(finding)
                    good(f"CSRF vulnerability (token present but not validated) on {form.action}")
                elif test_result == "protected":
                    debug(f"Token validated on {form.action}")
                else:
                    debug(f"Token validation test inconclusive on {form.action}")

        # --- 3. Advanced tests (if aggressive) ---
        if self.config.aggressive and is_state_changing and form.method.upper() == "POST":
            # Content-Type CSRF
            ct_result = self._test_content_type(form)
            if ct_result == "vulnerable":
                finding = Finding(
                    url=page_url,
                    form_action=form.action,
                    method=form.method,
                    token_present=token_present,
                    token_fields=form.token_fields,
                    csrf_type="Content-Type",
                    test_result="vulnerable",
                    severity="High",
                    confidence=0.90
                )
                findings.append(finding)
                good(f"Content-Type CSRF vulnerability on {form.action} (JSON accepted without token)")
            # Method-based CSRF
            mb_result = self._test_method_based(form)
            if mb_result == "vulnerable":
                finding = Finding(
                    url=page_url,
                    form_action=form.action,
                    method=form.method,
                    token_present=token_present,
                    token_fields=form.token_fields,
                    csrf_type="Method",
                    test_result="vulnerable",
                    severity="High",
                    confidence=0.85
                )
                findings.append(finding)
                good(f"Method-based CSRF vulnerability on {form.action} (GET also works)")
            # Referrer-based CSRF
            ref_result = self._test_referrer(form)
            if ref_result == "vulnerable":
                finding = Finding(
                    url=page_url,
                    form_action=form.action,
                    method=form.method,
                    token_present=token_present,
                    token_fields=form.token_fields,
                    csrf_type="Referrer",
                    test_result="vulnerable",
                    severity="High",
                    confidence=0.80
                )
                findings.append(finding)
                good(f"Referrer-based CSRF vulnerability on {form.action} (Referer not validated)")

        return findings

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
            description="Evil CSRF - Cross‑Site Request Forgery Detection Tool (All Variations)",
            formatter_class=argparse.RawTextHelpFormatter,
            epilog=(
                "Examples:\n"
                "  python Evil_CSRF.py -u http://localhost/dvwa/ --dvwa-login --mode scan\n"
                "  python Evil_CSRF.py -u https://example.com --mode crawl --depth 3\n"
                "  python Evil_CSRF.py -u https://target.com --test --aggressive --threads 10\n"
            )
        )
        parser.add_argument('-u', '--url', required=True, help='Target URL')
        parser.add_argument('--mode', choices=['crawl', 'scan'], default='scan',
                            help='crawl: discover forms only; scan: detect CSRF vulnerabilities')
        parser.add_argument('--depth', type=int, default=2, help='Crawl depth (default: 2)')
        parser.add_argument('--delay', type=float, default=0.5, help='Delay between requests (default: 0.5)')
        parser.add_argument('--timeout', type=int, default=10, help='Request timeout (default: 10)')
        parser.add_argument('--threads', type=int, default=5, help='Number of concurrent scan threads (default: 5)')
        parser.add_argument('--no-cookies', action='store_true', help='Disable cookies')
        parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
        parser.add_argument('--debug', action='store_true', help='Enable debug prints')
        parser.add_argument('--dvwa-login', action='store_true', help='Auto‑login to DVWA')
        parser.add_argument('--test', action='store_true', help='Enable active token validation tests (POST only)')
        parser.add_argument('--aggressive', action='store_true', help='Enable advanced tests: content-type, method, referrer')
        parser.add_argument('--tokens', type=str, default='',
                            help='Comma‑separated list of additional token field names (e.g., "my_csrf,sec_token")')
        parser.add_argument('--output', required=True, help='Output directory for JSON result (must exist)')
        args = parser.parse_args(args_list)

        global DEBUG
        DEBUG = bool(args.debug)

        custom_tokens = [t.strip() for t in args.tokens.split(',') if t.strip()]

        self.config = Config(
            timeout=args.timeout,
            delay=args.delay,
            use_cookies=not args.no_cookies,
            threads=args.threads,
            test_active=args.test,
            aggressive=args.aggressive,
            custom_tokens=custom_tokens
        )
        self._setup_logging(args.verbose)
        self.client = HttpClient(timeout=args.timeout, delay=args.delay, use_cookies=not args.no_cookies)
        self.scanner = Scanner(self.client, self.config)

        if args.dvwa_login or "dvwa" in args.url.lower():
            from urllib.parse import urlparse
            base_url = f"{urlparse(args.url).scheme}://{urlparse(args.url).netloc}/dvwa"
            if self.client.login_dvwa(base_url, username="admin", password="password", security="low"):
                info("DVWA authentication successful")
            else:
                warn("DVWA authentication failed, continuing")

        folder = args.output

        if args.mode == 'crawl':
            self.do_crawl(args.url, args.depth, folder, custom_tokens)
        else:
            self.do_scan(args.url, args.depth, folder, custom_tokens)

    def do_crawl(self, target: str, depth: int, folder: str, custom_tokens: List[str]) -> None:
        crawler = Crawler(target, depth=depth, client=self.client, token_names=custom_tokens)
        results = crawler.run()
        # No text file output; only JSON (but crawl doesn't produce findings, so we just log)
        info(f"Crawl complete. Discovered {len(results)} pages with forms.")

    def do_scan(self, target: str, depth: int, folder: str, custom_tokens: List[str]) -> None:
        crawler = Crawler(target, depth=depth, client=self.client, token_names=custom_tokens)
        results = crawler.run()
        if not results:
            warn("No forms discovered.")
            return

        tasks = []
        for res in results:
            for form in res.forms:
                tasks.append((res.url, form))

        info(f"Queued {len(tasks)} forms for CSRF scanning (using {self.config.threads} threads).")
        all_findings = []
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            future_to_task = {
                executor.submit(self.scanner.scan_form, url, form): (url, form)
                for url, form in tasks
            }
            for future in as_completed(future_to_task):
                url, form = future_to_task[future]
                try:
                    findings = future.result()
                    if findings:
                        all_findings.extend(findings)
                except Exception as e:
                    error(f"Error scanning form {form.action}: {e}")

        self.scanner.findings = all_findings
        if all_findings:
            save_json(folder, "csrf_scan_result.json",
                      {"target": target, "findings": [f.to_dict() for f in self.scanner.findings]})
            info(f"Found {len(all_findings)} CSRF issues.")
        else:
            warn("No CSRF vulnerabilities found.")

# ===========================
# Entry
# ===========================
if __name__ == "__main__":
    try:
        App().run(sys.argv[1:])
    except KeyboardInterrupt:
        print()
        warn("Interrupted by user.")